import asyncio
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from .models import BulkheadFull, QueueTimeout, Settings


class Bulkhead:
    """A single-loop FIFO with direct handoff to the oldest live waiter."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._active = 0
        self._queue: deque[asyncio.Future[None]] = deque()

    @property
    def active(self) -> int:
        return self._active

    @property
    def waiting(self) -> int:
        return len(self._queue)

    def _release(self) -> None:
        while self._queue:
            future = self._queue.popleft()
            if not future.done():
                future.set_result(None)
                return
        self._active -= 1

    async def _acquire(self) -> None:
        if self._active < self.settings.concurrency:
            self._active += 1
            return
        if self.waiting >= self.settings.queue_capacity:
            raise BulkheadFull("Dependency waiting capacity exhausted")
        if self.settings.queue_seconds == 0:
            raise QueueTimeout("Dependency queue waiting disabled")
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._queue.append(future)
        try:
            async with asyncio.timeout(self.settings.queue_seconds):
                await future
        except BaseException as exc:
            if future in self._queue:
                self._queue.remove(future)
            elif not future.cancelled():
                # Slot handed off before the awakened task ran. Pass it on.
                self._release()
            if isinstance(exc, TimeoutError):
                raise QueueTimeout("Dependency queue wait expired") from None
            raise

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        await self._acquire()
        try:
            yield
        finally:
            self._release()
