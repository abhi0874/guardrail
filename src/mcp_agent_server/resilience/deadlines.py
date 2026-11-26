import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

from .models import AttemptTimeout, DeadlineExceeded

T = TypeVar("T")


@dataclass(frozen=True)
class Deadline:
    expires_at: float
    clock: Callable[[], float]

    @classmethod
    def start(cls, seconds: float, clock: Callable[[], float]) -> "Deadline":
        return cls(clock() + seconds, clock)

    def remaining(self) -> float:
        left = self.expires_at - self.clock()
        if left <= 0:
            raise DeadlineExceeded("Dependency execution budget exhausted")
        return left

    async def attempt(self, seconds: float, invoke: Callable[[], Awaitable[T]]) -> T:
        remaining = self.remaining()
        total_is_shorter = remaining <= seconds
        end = self.clock() + seconds
        timer = asyncio.timeout(min(seconds, remaining))
        try:
            async with timer:
                result = await invoke()
        except TimeoutError:
            if not timer.expired():
                raise
            if total_is_shorter:
                raise DeadlineExceeded("Total dependency deadline expired") from None
            self.remaining()
            raise AttemptTimeout("Dependency attempt timed out") from None
        except Exception:
            self.remaining()
            raise
        self.remaining()
        if timer.expired() and total_is_shorter:
            raise DeadlineExceeded("Total dependency deadline expired")
        if timer.expired() or self.clock() >= end:
            raise AttemptTimeout("Dependency attempt timed out")
        return result
