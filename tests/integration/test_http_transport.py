import asyncio
from pathlib import Path

import pytest
from mcp import MCPError

from mcp_agent_server.adapters.outbox import Outbox
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.policy import load_policy
from mcp_agent_server.tools.models import Message
from mcp_agent_server.tools.registry import SPECS

from .http_support import client, listener
from .test_production_tools import key


@pytest.mark.asyncio
async def test_real_http_tools_and_isolation(audit_db: Path) -> None:
    outbox = Outbox()
    async with listener(audit_db, outbox=outbox) as (url, clients, settings):
        a, ar = clients.issue()
        b, br = clients.issue()
        note = {"title": "HTTP note", "body": "Synthetic"}
        msg = Message(recipient="ops-lab", subject="HTTP", body="Synthetic")
        gate = ApprovalGate(AuditStore(audit_db), load_policy())
        async with client(url, a) as ca, client(url, b) as cb:
            assert ca.protocol_version == "2026-07-28"
            names = [t.name for t in (await ca.list_tools()).tools]
            assert set(names) == set(SPECS)
            print("HTTP", url, "protocol", ca.protocol_version, "discovery", names)
            health = await ca.call_tool("health")
            assert health.structured_content and health.structured_content["status"] == "ok"
            print("HTTP health", health.structured_content)
            hits = await ca.call_tool("search_documents", {"query": "approval"})
            assert hits.structured_content and hits.structured_content["matches"]
            doc = await ca.call_tool("read_document", {"document_id": "approval-guide"})
            assert (
                doc.structured_content and doc.structured_content["document_id"] == "approval-guide"
            )
            print(
                "HTTP search/read", hits.structured_content, doc.structured_content["document_id"]
            )
            for replay in [False, True]:
                result = await ca.call_tool("write_note", note, meta=key("http-note"))
                assert result.structured_content == {"note_id": 1, "persisted": True}
                assert result.meta and result.meta["mcp-agent-server/replayed"] is replay
            for who, tool, args, op, expected in [
                (cb, "write_note", note, "http-note", "idempotency_key_conflict"),
                (ca, "send_message", msg.model_dump(), "message", "approval_required"),
                (
                    ca,
                    "fetch_url",
                    {"url": "https://docs.example.org"},
                    "fetch",
                    "fetch_destination_denied",
                ),
            ]:
                with pytest.raises(MCPError) as err:
                    await who.call_tool(tool, args, meta=key(op))
                assert err.value.data["code"] == expected
                print("HTTP denied", tool, expected)
            gate.issue(ar.authorization, "send_message", msg, issuer="http-test", ttl_seconds=60)
            with pytest.raises(MCPError) as denied:
                await cb.call_tool("send_message", msg.model_dump(), meta=key("b-message"))
            assert denied.value.data["code"] == "approval_required"
            await ca.call_tool("send_message", msg.model_dump(), meta=key("message"))
            replayed = await ca.call_tool("send_message", msg.model_dump(), meta=key("message"))
            assert replayed.meta and replayed.meta["mcp-agent-server/replayed"] is True
            with pytest.raises(MCPError) as reused:
                await ca.call_tool("send_message", msg.model_dump(), meta=key("new-message"))
            assert reused.value.data["code"] == "approval_consumed"

            async def read(who: object) -> None:
                # Distinct clients run concurrently on shared server infrastructure.
                from mcp import Client

                assert isinstance(who, Client)
                assert (await who.call_tool("health")).structured_content

            await asyncio.gather(*(read(c) for c in [ca, cb] * 5))
        with gate.store.transaction() as db:
            assert db.execute("SELECT count(*) FROM notes").fetchone() == (1,)
            assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (1,)
            contexts = db.execute("SELECT DISTINCT connection_id FROM audit_events").fetchall()
            assert set(contexts) == {(str(ar.identifier),), (str(br.identifier),)}
            assert all(
                row[0].startswith("transport=streamable-http;")
                for row in db.execute("SELECT argument_summary FROM audit_events")
            )
            assert db.execute("SELECT DISTINCT principal FROM audit_policy").fetchall() == [
                ("local-capability",)
            ]
        assert len(outbox.entries) == 1
        assert a.get_secret_value().encode() not in audit_db.read_bytes()
        print("HTTP notes=1 consumed_approvals=1 clients=2 isolated=True")
    print("HTTP shutdown clean registry_empty=True")
