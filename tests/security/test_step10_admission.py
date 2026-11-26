"""Adversarial checks at the quota, audit, approval and client-timeout boundaries."""

import asyncio
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from integration.audit_support import connected
from integration.http_support import client, listener
from integration.test_production_tools import BOOT, denial, key, operator
from mcp import MCPError
from mcp_types import REQUEST_TIMEOUT

from mcp_agent_server.adapters.outbox import Outbox
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails import rate_limiting
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.policy import load_policy
from mcp_agent_server.tools.models import Message


@pytest.mark.asyncio
async def test_rotate_capabilities_against_global_write_budget(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Install the same fresh singleton a new server process starts with.
    monkeypatch.setattr(rate_limiting, "_process", None)
    quota = dict(global_capacity=2, connection_capacity=4, global_refill=0.001)
    msg = Message(recipient="ops-lab", subject="Quota probe", body="Synthetic")
    outbox = Outbox()
    async with listener(audit_db, rate=quota, outbox=outbox) as (url, clients, _):
        first, _ = clients.issue()
        async with client(url, first) as owner:
            r = await owner.call_tool(
                "write_note", {"title": "Control", "body": "Local"}, meta=key("control")
            )
            assert r.structured_content == {"note_id": 1, "persisted": True}
            assert not (await owner.call_tool("health")).is_error
        for i in range(3):
            token, ref = clients.issue()
            ApprovalGate(AuditStore(audit_db), load_policy()).issue(
                ref.authorization, "send_message", msg, issuer="operator", ttl_seconds=60
            )
            async with client(url, token) as peer:
                with pytest.raises(MCPError) as denied:
                    await peer.call_tool("send_message", msg.model_dump(), meta=key(f"rotated-{i}"))
                assert denied.value.data["code"] == "rate_limit_exceeded"
                assert denied.value.data["message"] == "Rate limit reached (global)."
        with closing(sqlite3.connect(audit_db)) as db:
            assert db.execute(
                "SELECT count(*),count(consumed_event) FROM approvals"
            ).fetchone() == (3, 0)
            assert db.execute("SELECT title FROM notes").fetchall() == [("Control",)]
            assert db.execute("SELECT tool,state FROM operations").fetchall() == [
                ("write_note", "COMPLETED")
            ]
            assert db.execute(
                "SELECT count(DISTINCT connection_id) FROM audit_events "
                "WHERE phase='denied' AND status='not_executed'"
            ).fetchone() == (3,)
        assert not outbox.entries


@pytest.mark.asyncio
async def test_live_audit_corruption_cannot_spend_replacement_grant(audit_db: Path) -> None:
    msg = Message(recipient="ops-lab", subject="Receipt substitution", body="Synthetic")
    async with connected(audit_db, bootstrap=BOOT) as peer:
        await peer.call_tool("health")
        operator(audit_db, msg)
        original = await peer.call_tool("send_message", msg.model_dump(), meta=key("original"))
        assert (
            original.structured_content
            and original.structured_content["recorded_in_memory"] is True
        )
        operator(audit_db, msg)
        # A missing companion row leaves a valid database and an invalid historical receipt.
        with closing(sqlite3.connect(audit_db)) as db, db:
            assert (
                db.execute(
                    "DELETE FROM audit_policy WHERE event_id=(SELECT post_id FROM operations)"
                ).rowcount
                == 1
            )
        await denial(
            peer, "send_message", msg.model_dump(), "idempotency_evidence_invalid", "original"
        )
        assert (audit_db.parent / "outbox-count").read_text() == "1"
        with closing(sqlite3.connect(audit_db)) as db:
            assert db.execute(
                "SELECT count(*),count(consumed_event) FROM approvals"
            ).fetchone() == (2, 1)
        fresh = await peer.call_tool("send_message", msg.model_dump(), meta=key("replacement"))
        assert fresh.meta and fresh.meta["mcp-agent-server/replayed"] is False
        assert fresh.structured_content != original.structured_content
        assert (audit_db.parent / "outbox-count").read_text() == "2"
        with closing(sqlite3.connect(audit_db)) as db:
            assert db.execute(
                "SELECT decision FROM operation_attempts ORDER BY rowid"
            ).fetchall() == [("new",), ("denied",), ("new",)]
            assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (2,)
            assert db.execute("SELECT count(*) FROM notes").fetchone() == (0,)


# Hold the receipt writer in a test-only stdio child after the genuine outbox append.
# A persistent marker lets the parent distinguish a lost reply from a rejected call.
DELAY_RECEIPT = """
import time
from mcp_agent_server.idempotency.storage import OperationStore
save_receipt = OperationStore.save_receipt
def held(self, operation, receipt):
    (settings.audit_db.parent / 'receipt-held').touch()
    start = time.monotonic()
    while not (settings.audit_db.parent / 'release').exists():
        if time.monotonic() - start > 5:
            raise RuntimeError('fixture timed out')
        time.sleep(.01)
    return save_receipt(self, operation, receipt)
OperationStore.save_receipt = held
"""


@pytest.mark.asyncio
async def test_lost_message_reply_then_replay_and_key_rotation(audit_db: Path) -> None:
    boot = BOOT.replace("create_server(settings,", DELAY_RECEIPT + "\ncreate_server(settings,")
    msg = Message(recipient="ops-lab", subject="Lost reply", body="Single append")
    async with connected(audit_db, bootstrap=boot) as peer:
        await peer.call_tool("health")
        operator(audit_db, msg)
        pending = asyncio.create_task(
            peer.call_tool(
                "send_message", msg.model_dump(), meta=key("held"), read_timeout_seconds=0.75
            )
        )
        try:
            async with asyncio.timeout(3):
                while not (audit_db.parent / "receipt-held").exists():
                    await asyncio.sleep(0.01)
            with pytest.raises(MCPError) as timed:
                await pending
            assert timed.value.code == REQUEST_TIMEOUT
            await denial(peer, "send_message", msg.model_dump(), "approval_consumed", "rotated")
            assert (audit_db.parent / "outbox-count").read_text() == "1"
        finally:
            (audit_db.parent / "release").touch()
        # Either completion or interruption is permissible after a lost response.
        async with asyncio.timeout(3):
            with closing(sqlite3.connect(audit_db)) as db:
                while db.execute("SELECT state FROM operations").fetchone()[0] == "IN_PROGRESS":
                    await asyncio.sleep(0.01)
                (state,) = db.execute("SELECT state FROM operations").fetchone()
        if state == "COMPLETED":
            replayed = await peer.call_tool("send_message", msg.model_dump(), meta=key("held"))
            assert replayed.meta and replayed.meta["mcp-agent-server/replayed"] is True
            assert (
                replayed.structured_content
                and replayed.structured_content["recorded_in_memory"] is True
            )
        else:
            assert state == "OUTCOME_UNKNOWN"
            await denial(
                peer, "send_message", msg.model_dump(), "operation_outcome_unknown", "held"
            )
        assert (audit_db.parent / "outbox-count").read_text() == "1"
        with closing(sqlite3.connect(audit_db)) as db:
            assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (1,)
            assert db.execute(
                "SELECT count(*) FROM operation_attempts WHERE decision='new'"
            ).fetchone() == (1,)
            assert db.execute("SELECT count(*) FROM notes").fetchone() == (0,)
