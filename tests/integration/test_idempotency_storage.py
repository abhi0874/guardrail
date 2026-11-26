import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.errors import ErrorCode, GuardrailError

from .mutation_fixture import Fixture


@pytest.mark.asyncio
async def test_v2_migration_preserves_grants_and_history(audit_db: Path) -> None:
    f = Fixture(audit_db, uuid4())
    f.approve()
    assert not (await f.call())[0].error
    f.approve()
    tables = ["approvals", "audit_events", "audit_policy"]
    with f.store.transaction() as db:
        history = [db.execute(f"SELECT * FROM {name} ORDER BY rowid").fetchall() for name in tables]
        db.execute("DROP TABLE notes")
        db.execute("DROP TABLE operation_attempts")
        db.execute("DROP TABLE operations")
        db.execute("PRAGMA user_version=2")
    upgraded = Fixture(audit_db, f.conn)
    with upgraded.store.transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (4,)
        for name, before in zip(tables, history, strict=True):
            assert db.execute(f"SELECT * FROM {name} ORDER BY rowid").fetchall() == before
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert db.execute("SELECT count(*) FROM operations").fetchone() == (0,)
    result, _ = await upgraded.call()
    assert not result.error and upgraded.count() == 2
    print(
        "migration=2->4 preserved=consumed+unused_grants,pre+post,policy_metadata"
        " foreign_key_errors=0"
    )


@pytest.mark.asyncio
async def test_database_rejects_duplicate_and_terminal_update(audit_db: Path) -> None:
    f = Fixture(audit_db, uuid4())
    f.approve()
    await f.call()
    with f.store.transaction() as db:
        for sql in [
            "UPDATE operations SET state='RESERVED'",
            "UPDATE operations SET receipt='{}'",
            "INSERT INTO operations SELECT * FROM operations",
        ]:
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(sql)
    assert not (await f.call())[0].error


@pytest.mark.asyncio
async def test_incompatible_v3_fails_closed(audit_db: Path) -> None:
    f = Fixture(audit_db, uuid4())
    f.approve()
    with f.store.transaction() as db:
        db.execute("DROP TRIGGER operation_state_guard")
    with pytest.raises(GuardrailError):
        AuditStore(audit_db)
    e, r = await f.call()
    assert e.error and e.error.code is ErrorCode.AUDIT_UNAVAILABLE and r is None and f.calls == 0
