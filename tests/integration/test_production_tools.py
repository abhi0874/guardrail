import asyncio
import json
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

import pytest
from mcp import Client, MCPError, types
from pydantic import TypeAdapter

from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.authorization import LOCAL, AuthorizationContext
from mcp_agent_server.guardrails.policy import POLICIES, load_policy
from mcp_agent_server.tools.models import Message
from mcp_agent_server.tools.registry import SPECS

from .audit_support import connected, rows

BOOT = """
import httpx
from mcp_agent_server.config import Settings
from mcp_agent_server.server import create_server
from mcp_agent_server.adapters.http import Fetcher
from mcp_agent_server.adapters.outbox import Outbox
settings=Settings.from_env()
async def resolve(host):
    assert host=="docs.example.org"
    return ["93.184.216.34"]
def reply(request):
    assert request.url.host=="93.184.216.34"
    assert request.extensions["sni_hostname"]=="docs.example.org"
    return httpx.Response(200,headers={"content-type":"text/plain"},
                         stream=httpx.ByteStream(b"offline handbook"))
class ObservedOutbox(Outbox):
    def record(self,msg):
        receipt=super().record(msg)
        (settings.audit_db.parent/"outbox-count").write_text(str(len(self.entries)))
        return receipt
outbox=ObservedOutbox()
(settings.audit_db.parent/"outbox-count").write_text(str(len(outbox.entries)))
fetcher=Fetcher(settings.fetch_hosts,resolver=resolve,transport=lambda:httpx.MockTransport(reply))
create_server(settings,fetcher=fetcher,outbox=outbox).run(transport="stdio")
"""


def key(value: str) -> types.RequestParamsMeta:
    return TypeAdapter(types.RequestParamsMeta).validate_python(
        {"mcp-agent-server/idempotency-key": value}
    )


async def denial(
    client: Client, name: str, data: Mapping[str, object], expected: str, op: str = "key"
) -> None:
    with pytest.raises(MCPError) as error:
        await client.call_tool(name, dict(data), meta=key(op))
    assert error.value.data["code"] == expected and UUID(error.value.data["request_id"])


def operator(path: Path, msg: Message) -> None:
    gate = ApprovalGate(AuditStore(path), load_policy())
    context = AuthorizationContext(
        identity=LOCAL, connection_id=UUID(rows(path)[-1]["connection_id"])
    )
    gate.issue(context, "send_message", msg, issuer="test-operator", ttl_seconds=60)


@pytest.mark.asyncio
async def test_six_tool_demo(audit_db: Path) -> None:
    config = {"MCP_AGENT_FETCH_HOSTS": "docs.example.org"}
    msg = Message(recipient="ops-lab", subject="Drill", body="Synthetic test message")
    note = {"title": "Drill record", "body": "Synthetic exercise"}
    async with connected(audit_db, bootstrap=BOOT, limits=config) as client:
        listing = await client.list_tools()
        names = [tool.name for tool in listing.tools]
        assert sorted(names) == [
            "fetch_url",
            "health",
            "read_document",
            "search_documents",
            "send_message",
            "write_note",
        ]
        for tool in listing.tools:
            spec = SPECS[tool.name]
            assert tool.input_schema["properties"].keys() == spec.arguments.model_fields.keys()
            assert (
                tool.output_schema
                and tool.output_schema["properties"].keys() == spec.result.model_fields.keys()
            )
            assert tool.annotations and tool.annotations.read_only_hint is (spec.mutation is None)
        print("discovery", names, "protocol", client.protocol_version)
        health = (await client.call_tool("health")).structured_content
        assert health and health["status"] == "ok"
        hits = (
            await client.call_tool("search_documents", {"query": "approval", "limit": 1})
        ).structured_content
        assert hits and hits["matches"][0]["document_id"] == "approval-guide"
        result = (
            await client.call_tool(
                "read_document", {"document_id": hits["matches"][0]["document_id"]}
            )
        ).structured_content
        assert result and result["title"] == hits["matches"][0]["title"]
        print("health", health, "search/read", result["document_id"], result["title"])
        await denial(client, "read_document", {"document_id": "absent"}, "document_not_found")
        await denial(
            client, "read_document", {"document_id": "../escape"}, "invalid_tool_arguments"
        )
        for replay in [False, True]:
            n = await client.call_tool("write_note", note, meta=key("note-1"))
            assert n.structured_content == {"note_id": 1, "persisted": True} and n.meta
            assert n.meta["mcp-agent-server/replayed"] is replay
        await denial(
            client, "write_note", {**note, "body": "Changed"}, "idempotency_key_conflict", "note-1"
        )
        await denial(client, "send_message", msg.model_dump(), "approval_required", "msg-1")
        await denial(
            client,
            "send_message",
            {**msg.model_dump(), "approved": True},
            "invalid_tool_arguments",
            "msg-1",
        )
        await denial(
            client,
            "send_message",
            {**msg.model_dump(), "recipient": "external"},
            "invalid_tool_arguments",
        )
        operator(audit_db, msg)

        async def send() -> str:
            try:
                r = await client.call_tool("send_message", msg.model_dump(), meta=key("msg-1"))
                assert r.structured_content and r.structured_content["recorded_in_memory"] is True
                return str(r.structured_content["simulation_id"])
            except MCPError as error:
                assert error.data["code"] == "operation_in_progress"
                return ""

        ids = await asyncio.gather(*(send() for _ in range(6)))
        recorded = {i for i in ids if i}
        assert len(recorded) == 1
        replayed = await client.call_tool("send_message", msg.model_dump(), meta=key("msg-1"))
        assert replayed.meta and replayed.meta["mcp-agent-server/replayed"] is True
        assert (
            replayed.structured_content and replayed.structured_content["simulation_id"] in recorded
        )
        await denial(
            client,
            "send_message",
            {**msg.model_dump(), "subject": "Other"},
            "idempotency_key_conflict",
            "msg-1",
        )
        assert (audit_db.parent / "outbox-count").read_text() == "1"
        await denial(
            client, "fetch_url", {"url": "https://example.net/"}, "fetch_destination_denied"
        )
        page = (
            await client.call_tool("fetch_url", {"url": "https://docs.example.org/page"})
        ).structured_content
        assert page == {
            "host": "docs.example.org",
            "media_type": "text/plain",
            "text": "offline handbook",
        }
        print("note", n.structured_content, "message", replayed.structured_content, "fetch", page)
    store = AuditStore(audit_db)
    with store.transaction() as db:
        assert db.execute("SELECT title,body FROM notes").fetchall() == [
            (note["title"], note["body"])
        ]
        assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (1,)
        assert db.execute("SELECT count(*) FROM operations WHERE state='COMPLETED'").fetchone() == (
            2,
        )
        assert (
            db.execute(
                "SELECT count(*) FROM operation_attempts WHERE decision='replay'"
            ).fetchone()[0]
            >= 2
        )
        assert db.execute(
            "SELECT DISTINCT tool_name FROM audit_events ORDER BY tool_name"
        ).fetchall() == [(n,) for n in sorted(names)]
        pairs = db.execute("""SELECT a.tool_name FROM audit_events a JOIN audit_events z
            ON z.parent_event_id=a.event_id AND z.request_id=a.request_id
            WHERE a.phase='pre' AND z.status='succeeded' ORDER BY a.tool_name""").fetchall()
        assert pairs == [(name,) for name in sorted(names)]
        assert not db.execute("PRAGMA foreign_key_check").fetchall()
    print("persisted_notes=1 outbox_entries=1 approvals_consumed=1 completed_operations=2")
    async with connected(audit_db, bootstrap=BOOT, limits=config) as restarted:
        assert (audit_db.parent / "outbox-count").read_text() == "0"
        await denial(restarted, "write_note", note, "idempotency_key_conflict", "note-1")
        await denial(
            restarted, "send_message", msg.model_dump(), "idempotency_key_conflict", "msg-1"
        )
    # Business text belongs only in its designated store. Message bodies never enter SQLite.
    assert msg.body.encode() not in audit_db.read_bytes()


@pytest.mark.asyncio
async def test_note_concurrency_and_validation(audit_db: Path) -> None:
    async with connected(audit_db) as client:
        note = {"title": "Demo", "body": "Runbook practice"}

        async def create() -> bool:
            try:
                r = await client.call_tool("write_note", note, meta=key("race"))
                assert r.structured_content and r.structured_content["note_id"] == 1
                return True
            except MCPError as err:
                assert err.data["code"] == "operation_in_progress"
                return False

        assert any(await asyncio.gather(*(create() for _ in range(8))))
        await denial(client, "write_note", {"title": "", "body": "x"}, "invalid_tool_arguments")
        await denial(client, "write_note", {**note, "role": "admin"}, "invalid_tool_arguments")
        await denial(
            client, "fetch_url", {"url": "https://docs.example.org/"}, "fetch_destination_denied"
        )
    with AuditStore(audit_db).transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone() == (1,)


@pytest.mark.asyncio
async def test_expired_revoked_message_grants(audit_db: Path) -> None:
    async with connected(audit_db) as client:
        msg = Message(recipient="docs-lab", subject="Test", body="Synthetic")
        await denial(client, "send_message", msg.model_dump(), "approval_required")
        ctx = AuthorizationContext(
            identity=LOCAL, connection_id=UUID(rows(audit_db)[-1]["connection_id"])
        )
        gate = ApprovalGate(AuditStore(audit_db), load_policy(), clock=lambda: 1000)
        token = gate.issue(ctx, "send_message", msg, issuer="test-operator", ttl_seconds=1)
        await denial(client, "send_message", msg.model_dump(), "approval_expired")
        gate.revoke(token)
        await denial(client, "send_message", msg.model_dump(), "approval_revoked")
    with gate.store.transaction() as db:
        assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM operations").fetchone() == (0,)


@pytest.mark.asyncio
async def test_write_policy_denial_cannot_insert(audit_db: Path) -> None:
    doc = load_policy().document.model_dump(mode="json")
    next(r for r in doc["rules"] if r["tool"] == "write_note")["action"] = "deny"
    with TemporaryDirectory(dir=POLICIES) as directory:
        file = Path(directory) / "denied.yaml"
        file.write_text(json.dumps(doc))
        async with connected(audit_db, limits={"MCP_AGENT_POLICY": str(file)}) as client:
            await denial(client, "write_note", {"title": "Denied", "body": "Test"}, "policy_denied")
    with AuditStore(audit_db).transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM operations").fetchone() == (0,)
        assert db.execute("SELECT phase,error_code FROM audit_events").fetchall() == [
            ("denied", "policy_denied")
        ]
