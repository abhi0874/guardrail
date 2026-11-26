"""A single short critical section admits against both quotas or neither."""

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from mcp_agent_server.errors import ConfigurationError, ErrorCode, GuardrailError, PublicError

from .security_settings import RateSettings


class RateDenial(GuardrailError):
    def __init__(self, category: str):
        super().__init__(ErrorCode.RATE_LIMIT_EXCEEDED)
        self.public = PublicError(
            code=ErrorCode.RATE_LIMIT_EXCEEDED,
            retryable=True,
            message=f"Rate limit reached ({category}).",
        )


@dataclass(frozen=True)
class Bucket:
    tokens: float
    updated: float

    def available(self, now: float, capacity: int, rate: float) -> float:
        return min(capacity, self.tokens + (now - self.updated) * rate)


class RateLimiter:
    def __init__(self, settings: RateSettings, clock: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.clock = clock
        self._lock = threading.Lock()
        now = clock()
        if not math.isfinite(now):
            raise ValueError("Invalid monotonic clock")
        self._global = Bucket(settings.global_capacity, now)
        self._connections: dict[UUID, Bucket] = {}

    async def admit(self, connection: UUID) -> None:
        # No await, I/O or token wait inside the lock. Also supports distinct event loops.
        with self._lock:
            now = self.clock()
            if not math.isfinite(now):
                raise RateDenial("clock")
            now = max(now, self._global.updated)
            cfg = self.settings
            total = self._global.available(now, cfg.global_capacity, cfg.global_refill)
            if total < 1:
                raise RateDenial("global")
            bucket = self._connections.get(connection)
            if bucket is None:
                if len(self._connections) >= cfg.max_connections:
                    self._connections = {
                        k: b
                        for k, b in self._connections.items()
                        if now - b.updated < cfg.retention
                        or b.available(now, cfg.connection_capacity, cfg.connection_refill)
                        < cfg.connection_capacity
                    }
                    if len(self._connections) >= cfg.max_connections:
                        raise RateDenial("connection capacity")
                bucket = Bucket(cfg.connection_capacity, now)
            local = bucket.available(now, cfg.connection_capacity, cfg.connection_refill)
            if local < 1:
                raise RateDenial("connection")
            self._global = Bucket(total - 1, now)
            self._connections[connection] = Bucket(local - 1, now)


_process: RateLimiter | None = None
_process_lock = threading.Lock()


def process_limiter(settings: RateSettings) -> RateLimiter:
    global _process
    with _process_lock:
        if _process is None:
            _process = RateLimiter(settings)
        elif _process.settings != settings:
            raise ConfigurationError()
        return _process
