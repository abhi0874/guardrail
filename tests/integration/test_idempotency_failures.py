import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import BaseModel

from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.storage.connection import Connection

from .mutation_fixture import Fixture, increment


@pytest.mark.asyncio
@pytest.mark.parametrize("point", ["pre", "reservation_commit", "post", "local_rollback", "start"])
async def test_failure_boundaries(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    f = Fixture(audit_db, uuid4())
    f.approve()
    assert f.pipe.mutation_service
    operations = f.pipe.mutation_service.store
    original = f.store.insert_event
    transaction = f.store.transaction

    def bad_event(db: sqlite3.Connection, event: AuditEvent) -> None:
        if event.phase == point:
            raise sqlite3.OperationalError("private fixture detail")
        original(db, event)

    monkeypatch.setattr(f.store, "insert_event", bad_event)

    @contextmanager
    def bad_commit(
        *, create: bool = False, lock_timeout: float = 2
    ) -> Iterator[sqlite3.Connection]:
        with transaction(create=create, lock_timeout=lock_timeout) as db:
            assert isinstance(db, sqlite3.Connection)
            yield db
            if db.execute("SELECT count(*) FROM operations").fetchone()[0] == 1:
                # Deferred FK is checked by the real sqlite connection at COMMIT.
                db.execute("PRAGMA defer_foreign_keys=ON")
                db.execute("UPDATE operations SET pre_id='no-such-event'")

    if point == "reservation_commit":
        monkeypatch.setattr(f.store, "transaction", bad_commit)

    def fail_start(op: str) -> None:
        raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)

    if point == "start":
        monkeypatch.setattr(operations, "start", fail_start)

    def rollback(db: Connection) -> object:
        increment(db, 1)
        return {"count": "unpersistable-private-data"}

    async def dispatch(data: BaseModel) -> dict[str, object]:
        if point == "local_rollback":
            f.pipe.claim("increment")
            f.calls += 1
            assert f.pipe.mutation_service
            await f.pipe.mutation_service.local_effect(rollback)
            pytest.fail("invalid receipt should roll back")
        return await f.handler(data)

    e, r = await f.pipe.execute(f.request(), dispatch, idempotency_key="sample-key")
    expected = {
        "pre": ErrorCode.AUDIT_UNAVAILABLE,
        "reservation_commit": ErrorCode.AUDIT_UNAVAILABLE,
        "start": ErrorCode.STATE_CHANGE_FAILED,
        "post": ErrorCode.AUDIT_INTEGRITY,
        "local_rollback": ErrorCode.OPERATION_OUTCOME_UNKNOWN,
    }[point]
    assert e.error and e.error.code is expected and r is None and not e.error.retryable
    assert "private" not in e.error.message
    with transaction() as db:
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        states = db.execute("SELECT state,receipt FROM operations").fetchall()
        consumed = db.execute("SELECT count(consumed_event) FROM approvals").fetchone()[0]
    if point in ("pre", "reservation_commit"):
        assert not states and consumed == 0 and f.count() == f.calls == 0
    elif point == "start":
        assert (
            states == [("FAILED_BEFORE_EFFECT", None)]
            and consumed == 1
            and f.count() == f.calls == 0
        )
    else:
        assert states == [("OUTCOME_UNKNOWN", '{"count":1}' if point == "post" else None)]
        assert consumed == f.calls == 1 and f.count() == (1 if point == "post" else 0)
        again, result = await f.call()
        assert (
            again.error
            and again.error.code is ErrorCode.OPERATION_OUTCOME_UNKNOWN
            and result is None
        )
    print(
        f"fault={point} public={expected.value} rows={states}"
        f" consumed={consumed} counter={f.count()}"
    )


@pytest.mark.asyncio
async def test_cancel_admission_settles_worker_before_return(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio
    import threading

    f = Fixture(audit_db, uuid4())
    f.approve()
    entered = threading.Event()
    resume = threading.Event()
    original = f.store.insert_event

    def paused(db: sqlite3.Connection, event: AuditEvent) -> None:
        if event.phase == "pre":
            entered.set()
            assert resume.wait(3)
        original(db, event)

    monkeypatch.setattr(f.store, "insert_event", paused)
    task = asyncio.create_task(f.call())
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
    finally:
        resume.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert f.count() == f.calls == 0
    with f.store.transaction() as db:
        assert db.execute("SELECT state FROM operations").fetchone() == ("FAILED_BEFORE_EFFECT",)
        assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (1,)
        assert db.execute("SELECT status FROM audit_events WHERE phase='post'").fetchone() == (
            "not_executed",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked_table", ["operations", "approvals"])
async def test_reservation_or_grant_write_refused(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch, blocked_table: str
) -> None:
    f = Fixture(audit_db, uuid4())
    f.approve()
    original = f.store.transaction

    def authorizer(
        action: int, table: str | None, field: str | None, db_name: str | None, source: str | None
    ) -> int:
        if table == blocked_table and action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    @contextmanager
    def guarded(*, create: bool = False, lock_timeout: float = 2) -> Iterator[sqlite3.Connection]:
        with original(create=create, lock_timeout=lock_timeout) as db:
            assert isinstance(db, sqlite3.Connection)
            db.set_authorizer(authorizer)
            yield db

    monkeypatch.setattr(f.store, "transaction", guarded)
    outcome, result = await f.call()
    assert outcome.error and outcome.error.code == ErrorCode.AUDIT_UNAVAILABLE and result is None
    assert f.calls == f.count() == 0
    with original() as db:
        assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM operations").fetchone() == (0,)
        assert db.execute("SELECT phase FROM audit_events").fetchall() == [("denied",)]
