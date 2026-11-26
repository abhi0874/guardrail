import json
from pathlib import Path
from uuid import uuid4

import pytest
from mcp import MCPError, types
from pydantic import TypeAdapter

from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.tools.models import Message

from .audit_support import connected, rows
from .test_production_tools import BOOT, denial, key, operator

LIMITS = {
    "MCP_AGENT_RATE_CONNECTION_CAPACITY": "1",
    "MCP_AGENT_RATE_CONNECTION_REFILL": "0.001",
    "MCP_AGENT_RATE_GLOBAL_REFILL": "0.001",
}


@pytest.mark.asyncio
async def test_rate_denial_cannot_consume_approval_or_create_effect(audit_db: Path) -> None:
    msg = Message(recipient="ops-lab", subject="Drill", body="Synthetic")
    async with connected(audit_db, bootstrap=BOOT, limits=LIMITS) as client:
        result = await client.call_tool("health")
        assert result.meta and result.meta["mcp-agent-server/output"]["redactions"] == 0
        operator(audit_db, msg)
        await denial(client, "send_message", msg.model_dump(), "rate_limit_exceeded")
        await denial(
            client, "write_note", {"title": "Blocked", "body": "Local"}, "rate_limit_exceeded"
        )
        forged = TypeAdapter(types.RequestParamsMeta).validate_python(
            {"connection_id": str(uuid4()), "principal": "operator", "session_id": "fresh"}
        )
        with pytest.raises(MCPError) as error:
            await client.call_tool("health", meta=forged)
        data = error.value.data
        assert data["code"] == "rate_limit_exceeded" and data["retryable"] is True
        assert data["message"] == "Rate limit reached (connection)."
        assert str(forged) not in json.dumps(data)
        print("rate_denial", data)
        assert (audit_db.parent / "outbox-count").read_text() == "0"
    with AuditStore(audit_db).transaction() as db:
        assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM operations").fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM notes").fetchone() == (0,)
    denied = [r for r in rows(audit_db) if r["phase"] == "denied"]
    assert len(denied) == 3 and all(r["error_code"] == "rate_limit_exceeded" for r in denied)
    assert len({r["connection_id"] for r in rows(audit_db)}) == 1
    print("rate_denied=3 approvals_consumed=0 operations=0 notes=0 outbox=0")


@pytest.mark.asyncio
async def test_completed_note_replay_consumes_rate_capacity(audit_db: Path) -> None:
    config = {**LIMITS, "MCP_AGENT_RATE_CONNECTION_CAPACITY": "2"}
    async with connected(audit_db, limits=config) as client:
        for expected in [False, True]:
            r = await client.call_tool(
                "write_note", {"title": "One", "body": "Local"}, meta=key("one")
            )
            assert r.structured_content == {"note_id": 1, "persisted": True}
            assert r.meta and r.meta["mcp-agent-server/replayed"] is expected
            assert "mcp-agent-server/output" in r.meta
        await denial(
            client, "write_note", {"title": "One", "body": "Local"}, "rate_limit_exceeded", "one"
        )
    with AuditStore(audit_db).transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone() == (1,)
        assert db.execute("SELECT count(*) FROM operation_attempts").fetchone() == (2,)
    print("note=1 replay=filtered third_request=rate_limit_exceeded")


@pytest.mark.asyncio
async def test_rate_audit_failure_stays_closed(audit_db: Path) -> None:
    boot = (
        """
import sqlite3
from mcp_agent_server.audit.storage import AuditStore
original=AuditStore.append
def broken(self,event):
    if event.phase=="denied":
        raise sqlite3.OperationalError("synthetic denied-audit failure")
    return original(self,event)
AuditStore.append=broken
"""
        + BOOT
    )
    async with connected(audit_db, bootstrap=boot, limits=LIMITS) as client:
        await client.call_tool("health")
        await denial(
            client, "write_note", {"title": "Blocked", "body": "Local"}, "audit_unavailable"
        )
    with AuditStore(audit_db).transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM operations").fetchone() == (0,)
