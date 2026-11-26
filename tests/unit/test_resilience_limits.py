import asyncio
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from pydantic import ValidationError

from mcp_agent_server.resilience.bulkhead import Bulkhead
from mcp_agent_server.resilience.circuit_breaker import CircuitBreaker, State
from mcp_agent_server.resilience.deadlines import Deadline
from mcp_agent_server.resilience.models import (
    AttemptTimeout,
    BulkheadFull,
    CircuitOpen,
    DeadlineExceeded,
    QueueTimeout,
    Settings,
    TransientFailure,
)
from mcp_agent_server.resilience.retry import backoff


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize(
    "field,value",
    [
        ("attempts", 0),
        ("attempts", 17),
        ("attempt_seconds", -1),
        ("total_seconds", float("nan")),
        ("cooldown", 0),
        ("concurrency", 0),
        ("probes", 0),
        ("jitter", 2),
        ("queue_capacity", -1),
        ("backoff_cap", 0.01),
    ],
)
def test_invalid_limits(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({field: value})


def test_backoff_bounds_and_injected_jitter() -> None:
    s = Settings(attempts=5, backoff_base=1, backoff_cap=3, jitter=0.25)
    assert [backoff(s, n, lambda: 1.0) for n in range(1, 6)] == [1, 2, 3, 3, 3]
    assert backoff(s, 3, lambda: 0) == 2.25
    assert backoff(s, 3, lambda: 0.5) == 2.625
    with pytest.raises(ValueError):
        backoff(s, 6, lambda: 0)
    with pytest.raises(ValueError):
        backoff(s, 1, lambda: float("nan"))


@pytest.mark.asyncio
async def test_attempt_timeout_cleans_up_inline_and_total_rejects_late_results() -> None:
    clock = Clock()
    deadline = Deadline.start(1, clock)
    cleanup = []

    async def pending() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            cleanup.append(True)

    task = asyncio.current_task()
    with pytest.raises(AttemptTimeout):
        await deadline.attempt(0.01, pending)
    assert cleanup == [True] and asyncio.current_task() is task

    async def late() -> int:
        clock.now += 2
        return 3

    with pytest.raises(DeadlineExceeded):
        await deadline.attempt(1, late)


@pytest.mark.asyncio
async def test_late_and_unrelated_timeout_errors() -> None:
    clock = Clock()

    async def late() -> int:
        clock.now += 1
        return 4

    async def own_timeout() -> int:
        raise TimeoutError("adapter error")

    d = Deadline.start(5, clock)
    with pytest.raises(AttemptTimeout):
        await d.attempt(0.3, late)
    with pytest.raises(TimeoutError, match="adapter error"):
        await d.attempt(1, own_timeout)


@contextmanager
def failing(circuit: CircuitBreaker) -> Iterator[None]:
    with pytest.raises(TransientFailure), circuit.attempt():
        yield
        raise TransientFailure()


def test_circuit_threshold_and_half_open_recovery() -> None:
    clock = Clock()
    circuit = CircuitBreaker(Settings(failure_threshold=2, probes=2, cooldown=3), clock)
    with failing(circuit):
        pass
    with circuit.attempt():
        pass
    with failing(circuit):
        pass
    assert circuit.state.value == State.CLOSED
    with failing(circuit):
        pass
    assert circuit.state.value == State.OPEN
    with pytest.raises(CircuitOpen):
        circuit.check()
    clock.now += 3
    with circuit.attempt():
        assert circuit.state.value == State.HALF_OPEN
        with circuit.attempt():
            with pytest.raises(CircuitOpen):
                circuit.check()
        assert circuit.state.value == State.HALF_OPEN
    assert circuit.state.value == State.CLOSED


@pytest.mark.asyncio
async def test_stale_probe_and_cancelled_probe_slot() -> None:
    clock = Clock()
    circuit = CircuitBreaker(Settings(failure_threshold=1, probes=2, cooldown=2), clock)
    with failing(circuit):
        pass
    clock.now = 2
    entered = asyncio.Event()
    done = asyncio.Event()

    async def slow() -> None:
        with circuit.attempt():
            entered.set()
            await done.wait()

    stale = asyncio.create_task(slow())
    await entered.wait()
    with failing(circuit):
        pass
    done.set()
    await stale
    assert circuit.state.value == State.OPEN
    clock.now = 4
    entered.clear()
    done.clear()
    cancelled = asyncio.create_task(slow())
    await entered.wait()
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    with circuit.attempt():
        with circuit.attempt():
            pass
    assert circuit.state.value == State.CLOSED


@pytest.mark.asyncio
async def test_bulkhead_bounded_fifo_wait_and_cancellation() -> None:
    bulk = Bulkhead(Settings(concurrency=1, queue_capacity=2, queue_seconds=1))
    entered = []

    async def worker(n: int) -> None:
        async with bulk.slot():
            entered.append(n)
            assert bulk.active == 1

    async with bulk.slot():
        a = asyncio.create_task(worker(1))
        b = asyncio.create_task(worker(2))
        await asyncio.sleep(0)
        assert (bulk.active, bulk.waiting) == (1, 2)
        with pytest.raises(BulkheadFull):
            await worker(3)
        a.cancel()
        with pytest.raises(asyncio.CancelledError):
            await a
        c = asyncio.create_task(worker(4))
        await asyncio.sleep(0)
    await asyncio.gather(b, c)
    assert entered == [2, 4] and (bulk.active, bulk.waiting) == (0, 0)


@pytest.mark.asyncio
async def test_cancel_between_slot_handoff_and_resume() -> None:
    bulk = Bulkhead(Settings(concurrency=1, queue_capacity=2))
    entered = []

    async def worker(n: int) -> None:
        async with bulk.slot():
            entered.append(n)

    async with bulk.slot():
        a = asyncio.create_task(worker(1))
        b = asyncio.create_task(worker(2))
        await asyncio.sleep(0)
    a.cancel()
    with pytest.raises(asyncio.CancelledError):
        await a
    await b
    assert entered == [2] and (bulk.active, bulk.waiting) == (0, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("wait", [0, 0.01])
async def test_bulkhead_wait_timeout(wait: float) -> None:
    bulk = Bulkhead(Settings(concurrency=1, queue_capacity=1, queue_seconds=wait))
    async with bulk.slot():
        with pytest.raises(QueueTimeout):
            async with bulk.slot():
                pytest.fail("admitted")
        assert bulk.active == 1 and bulk.waiting == 0
    assert bulk.active == 0


@pytest.mark.asyncio
async def test_attempt_observes_shorter_total_and_late_failure() -> None:
    clock = Clock()

    async def slow() -> int:
        await asyncio.Event().wait()
        return 0

    async def exhausted() -> int:
        clock.now = 10
        raise TransientFailure()

    with pytest.raises(DeadlineExceeded):
        await Deadline.start(0.01, clock).attempt(1, slow)
    with pytest.raises(DeadlineExceeded):
        await Deadline.start(1, clock).attempt(4, exhausted)
