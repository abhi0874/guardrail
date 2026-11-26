"""Execute dependency attempts inside an existing, already claimed guardrail dispatch."""

import asyncio
import random
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TypeVar

from mcp_agent_server.guardrails.pipeline import Pipeline

from .bulkhead import Bulkhead
from .circuit_breaker import CircuitBreaker
from .deadlines import Deadline
from .models import DeadlineExceeded, Operation, Safety, Settings, TransientFailure
from .retry import backoff

T = TypeVar("T")


@dataclass(frozen=True)
class Dependency:
    settings: Settings
    circuit: CircuitBreaker
    bulkhead: Bulkhead


class ResilienceExecutor:
    def __init__(
        self,
        pipeline: Pipeline,
        dependencies: Mapping[str, Settings],
        *,
        clock: Callable[[], float] = time.monotonic,
        draw: Callable[[], float] = random.random,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.pipeline = pipeline
        self.clock = clock
        self.draw = draw
        self.sleep = sleep
        self.dependencies = {
            name: Dependency(settings, CircuitBreaker(settings, clock), Bulkhead(settings))
            for name, settings in dependencies.items()
        }
        self._loop: asyncio.AbstractEventLoop | None = None

    async def run(self, operation: Operation[T]) -> T:
        self.pipeline.require_claimed_dispatch()
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise RuntimeError("Executor belongs to another event loop")
        dep = self.dependencies[operation.dependency]
        deadline = Deadline.start(dep.settings.total_seconds, self.clock)
        timer = asyncio.timeout(deadline.remaining())
        try:
            async with timer:
                return await self._run(operation, dep, deadline)
        except TimeoutError:
            if timer.expired():
                raise DeadlineExceeded("Total dependency deadline expired") from None
            raise

    async def _run(self, operation: Operation[T], dep: Dependency, deadline: Deadline) -> T:
        settings = dep.settings
        attempts = settings.attempts if operation.safety is Safety.READ_ONLY else 1
        for attempt in range(1, attempts + 1):
            deadline.remaining()
            self.pipeline.require_claimed_dispatch()
            dep.circuit.check()
            try:
                async with dep.bulkhead.slot():
                    deadline.remaining()
                    self.pipeline.require_claimed_dispatch()
                    with dep.circuit.attempt():
                        return await deadline.attempt(settings.attempt_seconds, operation.invoke)
            except TransientFailure:
                if attempt == attempts:
                    raise
                # Refuse immediately if this failure opened the circuit.
                dep.circuit.check()
                delay = backoff(settings, attempt, self.draw)
                if delay >= deadline.remaining():
                    raise DeadlineExceeded("Remaining budget cannot accommodate backoff") from None
                await self.sleep(delay)
        raise AssertionError("Validated settings require at least one attempt")
