import json
from pathlib import Path
from uuid import UUID

import httpx
import pytest
from integration.audit_support import connected
from integration.http_support import client, listener
from integration.test_production_tools import key
from mcp import MCPError

from mcp_agent_server.adapters.http import Fetcher
from mcp_agent_server.config import Settings
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.authorization import LOCAL, AuthorizationContext
from mcp_agent_server.guardrails.policy import load_policy
from mcp_agent_server.storage.postgres import PostgresStore
from mcp_agent_server.tools.models import Message
from mcp_agent_server.tools.registry import SPECS

BOOT = """
from mcp_agent_server.config import Settings
from mcp_agent_server.server import create_server
from postgresql.test_protocol import fetcher
create_server(Settings.from_env(),fetcher=fetcher()).run(transport='stdio')
"""


def fetcher() -> Fetcher:
    async def resolve(host: str) -> list[str]:
        assert host == "docs.example.org"
        return ["93.184.216.34"]

    def reply(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "93.184.216.34"
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            stream=httpx.ByteStream(b"Synthetic PostgreSQL fixture"),
        )

    return Fetcher(
        ("docs.example.org",), resolver=resolve, transport=lambda: httpx.MockTransport(reply)
    )


@pytest.mark.asyncio
async def test_real_stdio_six_tools_and_restart(
    pg_store: PostgresStore, pg_settings: Settings, audit_db: Path
) -> None:
    assert pg_settings.database_url
    config = {
        "MCP_AGENT_STORAGE_BACKEND": "postgresql",
        "MCP_AGENT_DATABASE_URL": pg_settings.database_url.get_secret_value(),
        "MCP_AGENT_FETCH_HOSTS": "docs.example.org",
        "PYTHONPATH": str(Path.cwd() / "tests"),
    }
    message = Message(recipient="ops-lab", subject="Synthetic", body="Persisted simulation")
    for run in range(2):
        async with connected(audit_db, bootstrap=BOOT, limits=config) as peer:
            assert {t.name for t in (await peer.list_tools()).tools} == set(SPECS)
            assert (await peer.call_tool("health")).structured_content
            assert (
                await peer.call_tool("search_documents", {"query": "approval"})
            ).structured_content
            assert (
                await peer.call_tool("read_document", {"document_id": "approval-guide"})
            ).structured_content
            assert (
                await peer.call_tool("fetch_url", {"url": "https://docs.example.org/example"})
            ).structured_content
            with pg_store.transaction() as db:
                identifier = UUID(
                    db.execute(
                        "SELECT connection_id FROM audit_events ORDER BY timestamp DESC LIMIT 1"
                    ).fetchone()[0]
                )
            receipt = await peer.call_tool(
                "write_note",
                {"title": "Restart note", "body": "Persistent"},
                meta=key(f"restart-{run}"),
            )
            assert receipt.structured_content and receipt.structured_content["note_id"] == run + 1
            with pytest.raises(MCPError) as e:
                await peer.call_tool(
                    "send_message", message.model_dump(), meta=key(f"message-{run}")
                )
            assert e.value.data["code"] == "approval_required"
            gate = ApprovalGate(pg_store, load_policy())
            gate.issue(
                AuthorizationContext(connection_id=identifier, identity=LOCAL),
                "send_message",
                message,
                issuer="operator",
                ttl_seconds=60,
            )
            sent = await peer.call_tool(
                "send_message", message.model_dump(), meta=key(f"message-{run}")
            )
            replay = await peer.call_tool(
                "send_message", message.model_dump(), meta=key(f"message-{run}")
            )
            assert sent.structured_content == replay.structured_content
            assert replay.meta and replay.meta["mcp-agent-server/replayed"] is True
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM simulations").fetchone()[0] == 2
        assert (
            db.execute("SELECT count(*) FROM approvals WHERE consumed_at IS NOT NULL").fetchone()[0]
            == 2
        )
        assert (
            db.execute("SELECT count(*) FROM operations WHERE state='COMPLETED'").fetchone()[0] == 4
        )
    diagnostics = (audit_db.parent / "stderr.jsonl").read_text()
    assert pg_settings.database_url.get_secret_value() not in diagnostics
    for line in diagnostics.splitlines():
        assert "Traceback" not in line
        if line.startswith("{"):
            assert json.loads(line)["level"] in ("INFO", "WARNING")


@pytest.mark.asyncio
async def test_authenticated_http_isolation_and_approval(
    pg_store: PostgresStore, pg_settings: Settings, audit_db: Path
) -> None:
    async with listener(
        audit_db,
        storage_backend="postgresql",
        database_url=pg_settings.database_url,
        fetcher=fetcher(),
        fetch_hosts=("docs.example.org",),
    ) as (url, clients, _):
        a, ar = clients.issue()
        b, _ = clients.issue()
        async with client(url, a) as ca, client(url, b) as cb:
            assert len((await ca.list_tools()).tools) == 6
            for name, data in [
                ("health", {}),
                ("search_documents", {"query": "approval"}),
                ("read_document", {"document_id": "approval-guide"}),
                ("fetch_url", {"url": "https://docs.example.org/a"}),
            ]:
                assert (await ca.call_tool(name, data)).structured_content
            data = {"title": "Private synthetic note", "body": "Authorized"}
            first = await ca.call_tool("write_note", data, meta=key("http-note"))
            same = await ca.call_tool("write_note", data, meta=key("http-note"))
            assert first.structured_content == same.structured_content
            with pytest.raises(MCPError) as e:
                await cb.call_tool("write_note", data, meta=key("http-note"))
            assert e.value.data["code"] == "idempotency_key_conflict"
            message = Message(recipient="docs-lab", subject="Synthetic", body="Approved only")
            gate = ApprovalGate(pg_store, load_policy())
            gate.issue(ar.authorization, "send_message", message, issuer="operator", ttl_seconds=60)
            with pytest.raises(MCPError) as e:
                await cb.call_tool("send_message", message.model_dump(), meta=key("http-other"))
            assert e.value.data["code"] == "approval_required"
            sent = await ca.call_tool(
                "send_message", message.model_dump(), meta=key("http-approved")
            )
            replay = await ca.call_tool(
                "send_message", message.model_dump(), meta=key("http-approved")
            )
            assert sent.structured_content == replay.structured_content
            assert replay.meta and replay.meta["mcp-agent-server/replayed"] is True
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM simulations").fetchone()[0] == 1
        assert (
            db.execute("SELECT count(*) FROM approvals WHERE consumed_at IS NOT NULL").fetchone()[0]
            == 1
        )
