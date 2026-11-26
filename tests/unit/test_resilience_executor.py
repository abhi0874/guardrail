import asyncio
import sqlite3
from collections.abc import Awaitable, Callable
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import BaseModel

from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.authorization import LOCAL, AuthorizationContext
from mcp_agent_server.guardrails.models import GuardrailRequest
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.guardrails.validation import HealthArguments
from mcp_agent_server.resilience.executor import ResilienceExecutor
from mcp_agent_server.resilience.models import (
    AttemptTimeout,
    BulkheadFull,
    CircuitOpen,
    DeadlineExceeded,
    Operation,
    Safety,
    Settings,
    TransientFailure,
)

from .operations import Args, snapshot


def runtime(path: Path, settings: Settings) -> tuple[Pipeline, ResilienceExecutor]:
    pipe = Pipeline(AuditStore(path), {"health": HealthArguments}, 100, 2)
    return pipe, ResilienceExecutor(pipe, {"alpha": settings, "beta": settings})


async def authorized(pipe: Pipeline, body: Callable[[], Awaitable[None]]) -> None:
    errors = []

    async def handler(_: BaseModel) -> bool:
        pipe.claim("health")
        try:
            await body()
        except Exception as exc:
            errors.append(exc)
            raise
        return True

    execution, result = await pipe.execute(
        GuardrailRequest(connection_id=uuid4(), tool_name="health", arguments={}), handler
    )
    if errors:
        raise errors[0]
    assert result and execution.error is None


@pytest.mark.asyncio
async def test_retry_success_and_only_transient_reads_retry(audit_db: Path) -> None:
    pipe, executor = runtime(audit_db, Settings(attempts=3, backoff_base=0, failure_threshold=20))

    async def body() -> None:
        calls = 0

        async def transient() -> int:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise TransientFailure()
            return 7

        assert await executor.run(Operation("alpha", transient, Safety.READ_ONLY)) == 7
        assert calls == 3
        for failure in (
            ValueError(),
            TimeoutError(),
            GuardrailError(ErrorCode.APPROVAL_REQUIRED),
            GuardrailError(ErrorCode.AUDIT_UNAVAILABLE),
        ):
            count = 0

            async def permanent(error: Exception = failure) -> int:
                nonlocal count
                count += 1
                raise error

            with pytest.raises(type(failure)):
                await executor.run(Operation("alpha", permanent, Safety.READ_ONLY))
            assert count == 1
        calls = 0
        with pytest.raises(TransientFailure):
            await executor.run(Operation("alpha", transient))
        assert calls == 1

    await authorized(pipe, body)


@pytest.mark.asyncio
async def test_attempt_timeout_and_attempt_bound(audit_db: Path) -> None:
    pipe, executor = runtime(
        audit_db, Settings(attempt_seconds=0.01, attempts=3, backoff_base=0, failure_threshold=9)
    )
    calls = []

    async def pending() -> int:
        try:
            await asyncio.Event().wait()
        finally:
            calls.append(1)
        return 1

    async def body() -> None:
        with pytest.raises(AttemptTimeout):
            await executor.run(Operation("alpha", pending, Safety.READ_ONLY))
        assert len(calls) == 3 and executor.dependencies["alpha"].bulkhead.active == 0

    await authorized(pipe, body)


@pytest.mark.asyncio
async def test_deadline_does_not_reset_between_attempts(audit_db: Path) -> None:
    pipe, _ = runtime(audit_db, Settings())
    now = 0.0
    waits = []

    async def sleep(delay: float) -> None:
        nonlocal now
        waits.append(delay)
        now += delay

    executor = ResilienceExecutor(
        pipe,
        {
            "alpha": Settings(
                total_seconds=1,
                attempt_seconds=0.8,
                attempts=6,
                backoff_base=0.2,
                backoff_cap=0.4,
                failure_threshold=10,
            )
        },
        clock=lambda: now,
        sleep=sleep,
    )
    calls = []

    async def fail() -> int:
        nonlocal now
        calls.append(now)
        now += 0.35
        raise TransientFailure()

    async def body() -> None:
        with pytest.raises(DeadlineExceeded):
            await executor.run(Operation("alpha", fail, Safety.READ_ONLY))
        assert len(calls) == 2 and waits == [0.2]

    await authorized(pipe, body)


@pytest.mark.asyncio
async def test_deadline_in_queue_and_overload_do_not_invoke(audit_db: Path) -> None:
    pipe, executor = runtime(
        audit_db, Settings(total_seconds=0.05, concurrency=1, queue_seconds=3, queue_capacity=1)
    )
    bulk = executor.dependencies["alpha"].bulkhead
    calls = []

    async def op() -> int:
        calls.append(1)
        return 1

    async def body() -> None:
        async with bulk.slot():
            queued = asyncio.create_task(executor.run(Operation("alpha", op, Safety.READ_ONLY)))
            await asyncio.sleep(0)
            assert bulk.waiting == 1
            with pytest.raises(BulkheadFull):
                await executor.run(Operation("alpha", op, Safety.READ_ONLY))
            with pytest.raises(DeadlineExceeded):
                await queued
            assert bulk.active == 1 and bulk.waiting == 0
        assert not calls and bulk.active == 0

    await authorized(pipe, body)


@pytest.mark.asyncio
async def test_backoff_releases_capacity_and_total_caps_sleep(audit_db: Path) -> None:
    pipe, _ = runtime(audit_db, Settings())
    sleeping = asyncio.Event()
    cleaned = []

    async def backoff(_: float) -> None:
        sleeping.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.append(True)

    executor = ResilienceExecutor(
        pipe,
        {"alpha": Settings(total_seconds=0.15, concurrency=1, backoff_base=0.001)},
        sleep=backoff,
    )
    count = 0

    async def transient() -> int:
        nonlocal count
        count += 1
        raise TransientFailure()

    async def healthy() -> int:
        return 3

    async def body() -> None:
        first = asyncio.create_task(executor.run(Operation("alpha", transient, Safety.READ_ONLY)))
        await asyncio.wait_for(sleeping.wait(), 1)
        assert executor.dependencies["alpha"].bulkhead.active == 0
        assert await executor.run(Operation("alpha", healthy)) == 3
        with pytest.raises(DeadlineExceeded):
            await first
        assert cleaned == [True] and count == 1

    await authorized(pipe, body)


@pytest.mark.asyncio
async def test_circuit_open_no_retry_storm_and_isolation(audit_db: Path) -> None:
    pipe, executor = runtime(audit_db, Settings(failure_threshold=1, attempts=8))
    calls = 0

    async def down() -> int:
        nonlocal calls
        calls += 1
        raise TransientFailure()

    async def healthy() -> str:
        return "ok"

    async def body() -> None:
        for _ in range(3):
            with pytest.raises(CircuitOpen):
                await executor.run(Operation("alpha", down, Safety.READ_ONLY))
        assert calls == 1
        assert await executor.run(Operation("beta", healthy)) == "ok"
        assert executor.dependencies["alpha"].bulkhead is not executor.dependencies["beta"].bulkhead

    await authorized(pipe, body)


@pytest.mark.asyncio
async def test_cancelled_caller_releases_active_attempt(audit_db: Path) -> None:
    pipe, executor = runtime(audit_db, Settings())
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def pending() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    async def body() -> None:
        await executor.run(Operation("alpha", pending, Safety.READ_ONLY))

    task = asyncio.create_task(authorized(pipe, body))
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stopped.is_set() and executor.dependencies["alpha"].bulkhead.active == 0
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("SELECT status FROM audit_events WHERE phase='post'").fetchone() == (
            "interrupted",
        )


@pytest.mark.asyncio
async def test_dependency_cannot_establish_or_reuse_authorization(audit_db: Path) -> None:
    pipe, executor = runtime(audit_db, Settings())
    calls = 0

    async def op() -> int:
        nonlocal calls
        calls += 1
        return 1

    with pytest.raises(GuardrailError):
        await executor.run(Operation("alpha", op, Safety.READ_ONLY))

    async def handler(_: BaseModel) -> int:
        return await executor.run(Operation("alpha", op, Safety.READ_ONLY))

    execution, _ = await pipe.execute(
        GuardrailRequest(connection_id=uuid4(), tool_name="unknown", arguments={}), handler
    )
    assert execution.error and execution.error.code == ErrorCode.UNKNOWN_TOOL
    assert calls == 0
    # A pre-event by itself is insufficient; business dispatch must claim it.
    execution, _ = await pipe.execute(
        GuardrailRequest(connection_id=uuid4(), tool_name="health", arguments={}), handler
    )
    assert execution.error and calls == 0


@pytest.mark.asyncio
async def test_approved_invocation_retries_only_inner_read(audit_db: Path) -> None:
    store = AuditStore(audit_db)
    policy = snapshot()
    pipe = Pipeline(store, {"write": Args}, 2048, 4, policy=policy)
    executor = ResilienceExecutor(pipe, {"data": Settings(backoff_base=0)})
    ctx = AuthorizationContext(connection_id=uuid4(), identity=LOCAL)
    args = Args(recipient="inbox", number=1, category="a")

    def request() -> GuardrailRequest:
        return GuardrailRequest(
            connection_id=ctx.connection_id, tool_name="write", arguments=args.model_dump()
        )

    ops = []
    handlers = []

    async def lookup() -> str:
        ops.append(1)
        if len(ops) == 1:
            raise TransientFailure()
        return "record"

    async def handler(_: BaseModel) -> str:
        pipe.claim("write")
        handlers.append(1)
        return await executor.run(Operation("data", lookup, Safety.READ_ONLY))

    denied, _ = await pipe.execute(request(), handler)
    assert denied.error and denied.error.code == ErrorCode.APPROVAL_REQUIRED
    ApprovalGate(store, policy).issue(ctx, "write", args, issuer="operator", ttl_seconds=60)
    allowed, result = await pipe.execute(request(), handler)
    assert allowed.error is None and result == "record"
    replay, _ = await pipe.execute(request(), handler)
    assert replay.error and replay.error.code == ErrorCode.APPROVAL_USED
    assert len(ops) == 2 and len(handlers) == 1
    with closing(sqlite3.connect(audit_db)) as db:
        assert dict(db.execute("SELECT phase,count(*) FROM audit_events GROUP BY phase")) == {
            "denied": 2,
            "pre": 1,
            "post": 1,
        }
        assert db.execute(
            "SELECT count(*) FROM approvals WHERE consumed_event IS NOT NULL"
        ).fetchone() == (1,)
    print("1 approval consumed, 1 pre/post pair, 1 handler, 2 inner read attempts")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "phase,expected,calls",
    [("pre", ErrorCode.AUDIT_UNAVAILABLE, 0), ("post", ErrorCode.AUDIT_INTEGRITY, 1)],
)
async def test_outer_audit_failure_is_never_retried(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch, phase: str, expected: ErrorCode, calls: int
) -> None:
    from mcp_agent_server.audit.models import AuditEvent

    store = AuditStore(audit_db)
    pipe = Pipeline(store, {"health": HealthArguments}, 100, 2)
    executor = ResilienceExecutor(pipe, {"data": Settings(attempts=5)})
    writes = []
    invoked = []
    append = store.append

    def audited(event: AuditEvent) -> None:
        writes.append(event.phase)
        if event.phase == phase:
            raise RuntimeError("injected audit failure")
        append(event)

    monkeypatch.setattr(store, "append", audited)

    async def dependency() -> int:
        invoked.append(True)
        return 1

    async def handler(_: BaseModel) -> int:
        pipe.claim("health")
        return await executor.run(Operation("data", dependency, Safety.READ_ONLY))

    outcome, _ = await pipe.execute(
        GuardrailRequest(connection_id=uuid4(), tool_name="health", arguments={}), handler
    )
    assert outcome.error and outcome.error.code == expected
    assert writes == (["pre"] if phase == "pre" else ["pre", "post"])
    assert len(invoked) == calls


@pytest.mark.asyncio
async def test_other_dependency_runs_while_first_is_saturated(audit_db: Path) -> None:
    pipe, executor = runtime(audit_db, Settings(concurrency=1, queue_capacity=0))

    async def op() -> str:
        return "ok"

    async def body() -> None:
        async with executor.dependencies["alpha"].bulkhead.slot():
            with pytest.raises(BulkheadFull):
                await executor.run(Operation("alpha", op, Safety.READ_ONLY))
            assert await executor.run(Operation("beta", op, Safety.READ_ONLY)) == "ok"

    await authorized(pipe, body)


@pytest.mark.asyncio
async def test_total_timer_cancels_longer_attempt_once(audit_db: Path) -> None:
    pipe, executor = runtime(audit_db, Settings(total_seconds=0.025, attempt_seconds=1, attempts=5))
    exits = []

    async def slow() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            exits.append(True)

    async def body() -> None:
        with pytest.raises(DeadlineExceeded):
            await executor.run(Operation("alpha", slow, Safety.READ_ONLY))
        assert exits == [True] and executor.dependencies["alpha"].bulkhead.active == 0

    await authorized(pipe, body)
