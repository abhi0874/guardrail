from pathlib import Path
from uuid import uuid4

import pytest

from mcp_agent_server.audit.storage import AuditStore

from .audit_support import connected
from .mutation_fixture import Fixture
from .test_production_tools import BOOT, denial, key


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["pre", "post", "success"])
async def test_note_reopen_and_audit_faults(audit_db: Path, phase: str) -> None:
    # Only this test's host establishes a previous connection UUID across process starts.
    conn = uuid4()
    prefix = f"""
from mcp_agent_server.guardrails.middleware import ToolMiddleware
from mcp_agent_server.audit.storage import AuditStore
from uuid import UUID
import sqlite3
original=ToolMiddleware.__init__
def initialize(self,*args,**kwargs):
    original(self,*args,**kwargs)
    self.connection_id=UUID("{conn}")
ToolMiddleware.__init__=initialize
"""
    fault = f"""
insert=AuditStore.insert_event
def inject(db,event):
    if event.phase=={phase!r} and event.tool_name=="write_note":
        raise sqlite3.OperationalError("synthetic failure")
    insert(db,event)
AuditStore.insert_event=staticmethod(inject)
"""
    args = {"title": "Recovery", "body": "Synthetic"}
    cfg = {"MCP_AGENT_FETCH_HOSTS": "docs.example.org"}
    async with connected(audit_db, bootstrap=prefix + fault + BOOT, limits=cfg) as client:
        if phase == "success":
            r = await client.call_tool("write_note", args, meta=key("n"))
            assert r.structured_content == {"note_id": 1, "persisted": True}
        else:
            await denial(
                client,
                "write_note",
                args,
                "audit_unavailable" if phase == "pre" else "audit_integrity_failure",
                "n",
            )
    async with connected(audit_db, bootstrap=prefix + BOOT, limits=cfg) as restarted:
        if phase == "success":
            r = await restarted.call_tool("write_note", args, meta=key("n"))
            assert r.meta and r.meta["mcp-agent-server/replayed"] is True
            assert r.structured_content == {"note_id": 1, "persisted": True}
        elif phase == "post":
            await denial(restarted, "write_note", args, "operation_outcome_unknown", "n")
    with AuditStore(audit_db).transaction() as db:
        count = db.execute("SELECT count(*) FROM notes").fetchone()[0]
        assert count == (0 if phase == "pre" else 1)
        states = db.execute("SELECT state FROM operations").fetchall()
        assert (
            states
            == {"pre": [], "post": [("OUTCOME_UNKNOWN",)], "success": [("COMPLETED",)]}[phase]
        )
        print("note fault", phase, "rows", count, "operations", states)


@pytest.mark.asyncio
async def test_v3_migrates_completed_rows(audit_db: Path) -> None:
    f = Fixture(audit_db, uuid4())
    f.approve()
    assert not (await f.call())[0].error
    with f.store.transaction() as db:
        db.execute("DROP TABLE notes")
        db.execute("PRAGMA user_version=3")
        before = db.execute("SELECT * FROM operations").fetchall()
    upgraded = Fixture(audit_db, f.conn)
    result, replay = await upgraded.call()
    assert not result.error and replay and replay["_meta"] == {"mcp-agent-server/replayed": True}
    with upgraded.store.transaction() as db:
        assert db.execute("SELECT * FROM operations").fetchall() == before
        assert db.execute("SELECT count(*) FROM notes").fetchone() == (0,)
        assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (1,)
        assert db.execute("PRAGMA user_version").fetchone() == (4,)
