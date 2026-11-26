import asyncio
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import pytest

from mcp_agent_server.errors import ErrorCode, GuardrailError

from .mutation_fixture import Fixture, fixture_policy

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize(
    "mode,exit_code,state,count,error",
    [
        ("complete", 0, "COMPLETED", 1, None),
        ("before", 73, "FAILED_BEFORE_EFFECT", 0, ErrorCode.STATE_CHANGE_FAILED),
        ("external", 75, "OUTCOME_UNKNOWN", 0, ErrorCode.OPERATION_OUTCOME_UNKNOWN),
        ("after", 74, "OUTCOME_UNKNOWN", 1, ErrorCode.OPERATION_OUTCOME_UNKNOWN),
    ],
)
async def test_actual_process_restart(
    audit_db: Path, mode: str, exit_code: int, state: str, count: int, error: ErrorCode | None
) -> None:
    conn = uuid4()
    Fixture(audit_db, conn).approve()
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        str(Path(__file__).with_name("mutation_fixture.py")),
        str(audit_db),
        str(conn),
        mode,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    async with asyncio.timeout(10):
        stdout, stderr = await child.communicate()
    assert child.returncode == exit_code, stderr.decode()
    if mode == "complete":
        assert b'"count": 1' in stdout
    reopened = Fixture(audit_db, conn)
    assert reopened.pipe.mutation_service
    # Move only the trusted reconciliation clock past the persisted lease.
    reopened.pipe.mutation_service.store.clock = lambda: 4_000_000_000
    if mode != "complete":
        denied = Fixture(audit_db, conn, policy=fixture_policy(action="deny", approval=False))
        resp, _ = await denied.call()
        assert resp.error and resp.error.code is ErrorCode.POLICY_DENIED
        with reopened.store.transaction() as db:
            assert db.execute("SELECT state FROM operations").fetchone() == (
                "RESERVED" if mode == "before" else "IN_PROGRESS",
            )
    for _ in range(2):
        e, result = await reopened.call()
        if error is None:
            assert not e.error and result and result["_meta"] == {"mcp-agent-server/replayed": True}
            assert result["structuredContent"] == {"count": 1}
        else:
            assert e.error and e.error.code is error and not e.error.retryable and result is None
    assert reopened.calls == 0 and reopened.count() == count
    with reopened.store.transaction() as db:
        op, stored, receipt = db.execute(
            "SELECT operation_id,state,receipt FROM operations"
        ).fetchone()
        assert stored == state
        assert receipt == ('{"count":1}' if count else None)
        assert db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone() == (1,)
    if mode == "external":
        with closing(sqlite3.connect(audit_db.with_name("resource.sqlite3"))) as resource:
            assert resource.execute("SELECT sum(value) FROM delivered").fetchone() == (1,)
        print("independent_resource=1 durable_receipt=absent")
    with pytest.raises(GuardrailError):
        reopened.pipe.mutation_service.store.start(op)
    print(
        f"child_exit={exit_code} window={mode} reopened_state={state}"
        f" counter={count} new_dispatches=0"
    )
