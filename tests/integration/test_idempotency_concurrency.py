import asyncio
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import BaseModel

from mcp_agent_server.errors import ErrorCode

from .mutation_fixture import Fixture

pytestmark = pytest.mark.asyncio


async def test_competing_instances(audit_db: Path) -> None:
    conn = uuid4()
    fixtures = [Fixture(audit_db, conn) for _ in range(8)]
    for f in fixtures:
        f.approve()
    entered, release = asyncio.Event(), asyncio.Event()

    async def blocked(data: BaseModel) -> dict[str, object]:
        result = await fixtures[0].handler(data)
        entered.set()
        await release.wait()
        return result

    owner = asyncio.create_task(
        fixtures[0].pipe.execute(fixtures[0].request(), blocked, idempotency_key="sample-key")
    )
    async with asyncio.timeout(4):
        await entered.wait()
        calls = await asyncio.gather(*(f.call() for f in fixtures[1:]))
        assert all(
            e.error and e.error.code is ErrorCode.OPERATION_IN_PROGRESS and r is None
            for e, r in calls
        )
        conflict, _ = await fixtures[1].call(2)
        assert conflict.error and conflict.error.code is ErrorCode.IDEMPOTENCY_KEY_CONFLICT
        release.set()
        assert not (await owner)[0].error
    assert sum(f.calls for f in fixtures) == fixtures[0].count() == 1
    with fixtures[0].store.transaction() as db:
        assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (1,)
    print("workers=8 pending=7 conflict=1 persisted_counter=1 grants_consumed=1")


async def test_simultaneous_claims(audit_db: Path) -> None:
    conn = uuid4()
    fixtures = [Fixture(audit_db, conn) for _ in range(8)]
    fixtures[0].approve()
    records = await asyncio.gather(*(f.call() for f in fixtures))
    assert all(not e.error or e.error.code is ErrorCode.OPERATION_IN_PROGRESS for e, _ in records)
    assert sum(f.calls for f in fixtures) == fixtures[0].count() == 1


@pytest.mark.parametrize("timeout", [False, True])
async def test_cancel_or_timeout_cannot_rerun(audit_db: Path, timeout: bool) -> None:
    f = Fixture(audit_db, uuid4(), seconds=0.3 if timeout else 5)
    entered = asyncio.Event()
    f.approve()

    async def hang(data: BaseModel) -> dict[str, object]:
        result = await f.handler(data)
        entered.set()
        await asyncio.Event().wait()
        return result

    task = asyncio.create_task(f.pipe.execute(f.request(), hang, idempotency_key="sample-key"))
    async with asyncio.timeout(4):
        await entered.wait()
        if timeout:
            e, _ = await task
            assert e.error and e.error.code is ErrorCode.OPERATION_OUTCOME_UNKNOWN
        else:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    for _ in range(2):
        e, r = await f.call()
        assert (
            e.error
            and not e.error.retryable
            and e.error.code is ErrorCode.OPERATION_OUTCOME_UNKNOWN
            and r is None
        )
    assert f.calls == f.count() == 1
    with f.store.transaction() as db:
        assert db.execute("SELECT state,receipt FROM operations").fetchone() == (
            "OUTCOME_UNKNOWN",
            '{"count":1}',
        )
    print(f"timeout={timeout} state=OUTCOME_UNKNOWN attempts=1 persisted_counter=1")
