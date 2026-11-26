"""Owned, bounded persistence: cancellation never discards the commit observer."""

import asyncio
import contextvars
import logging
import math
import threading
from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic
from typing import Any, Generic, ParamSpec, TypeVar, cast

from anyio import CancelScope
from anyio.lowlevel import checkpoint_if_cancelled

from ..errors import ErrorCode, GuardrailError
from ..logging import LOGGER

P = ParamSpec("P")
T = TypeVar("T")


@dataclass(frozen=True)
class Boundary:
    deadline: float
    expired: threading.Event


_boundary: contextvars.ContextVar[Boundary | None] = contextvars.ContextVar(
    "persistence_boundary", default=None
)


def checkpoint() -> None:
    """Called before BEGIN and immediately before COMMIT; expiry rolls back."""
    boundary = _boundary.get()
    if boundary and (boundary.expired.is_set() or monotonic() >= boundary.deadline):
        raise GuardrailError(ErrorCode.AUDIT_INTEGRITY)


@dataclass(frozen=True)
class Settled(Generic[T]):
    value: T
    cancellation: asyncio.CancelledError | None

    @property
    def cancelled(self) -> bool:
        return self.cancellation is not None


class Persistence:
    """No detached asyncio tasks; every daemon worker retains its supervisor.

    SQLite busy waits are bounded at two seconds. A stalled OS/custom sink cannot
    be forcibly killed by Python: expiry returns an integrity error, fences future
    transactions, and keeps the worker observed until completion or process exit.
    """

    def __init__(self, seconds: float = 3):
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("Positive finite persistence deadline required")
        self.seconds = seconds
        self._pending: set[asyncio.Future[Any]] = set()
        self._closed = False
        self._expired: set[asyncio.Future[Any]] = set()

    @property
    def pending(self) -> int:
        return len(self._pending)

    async def settle(self, fn: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> Settled[T]:
        if self._closed or self._expired or len(self._pending) >= 128:
            raise GuardrailError(ErrorCode.AUDIT_INTEGRITY)
        loop = asyncio.get_running_loop()
        future: asyncio.Future[T] = loop.create_future()
        boundary = Boundary(monotonic() + self.seconds, threading.Event())
        context = contextvars.copy_context()
        self._pending.add(future)

        def finished(value: T | None, failure: BaseException | None) -> None:
            self._pending.discard(future)
            self._expired.discard(future)
            if failure is not None:
                future.set_exception(failure)
                future.exception()  # Observe late failures even after a deadline.
                if boundary.expired.is_set():
                    logging.getLogger(LOGGER).error(
                        "Expired persistence worker failed",
                        extra={"error_code": ErrorCode.AUDIT_INTEGRITY},
                    )
            else:
                # The successful path always supplies the callable's actual return.
                future.set_result(cast(T, value))

        def invoke() -> T:
            token = _boundary.set(boundary)
            try:
                checkpoint()
                return fn(*args, **kwargs)
            finally:
                _boundary.reset(token)

        def worker() -> None:
            value = None
            failure = None
            try:
                value = context.run(invoke)
            except BaseException as exc:
                failure = exc
            try:
                loop.call_soon_threadsafe(finished, value, failure)
            except RuntimeError:
                # Event loop already closed after bounded shutdown; never print payloads.
                logging.getLogger(LOGGER).error(
                    "Persistence completed after event loop shutdown",
                    extra={"error_code": ErrorCode.AUDIT_INTEGRITY},
                )

        cancellation = None
        with CancelScope(shield=True):
            try:
                threading.Thread(target=worker, name="mcp-persistence", daemon=True).start()
            except Exception:
                self._pending.discard(future)
                future.cancel()
                raise
            while not future.done():
                remaining = boundary.deadline - monotonic()
                if remaining <= 0:
                    boundary.expired.set()
                    self._expired.add(future)
                    logging.getLogger(LOGGER).error(
                        "Persistence deadline exceeded",
                        extra={"error_code": ErrorCode.AUDIT_INTEGRITY},
                    )
                    raise GuardrailError(ErrorCode.AUDIT_INTEGRITY)
                try:
                    await asyncio.wait({future}, timeout=remaining)
                except asyncio.CancelledError as exc:
                    cancellation = exc
            # Read/raise the actual storage result before honoring cancellation.
            value = future.result()
        try:
            await checkpoint_if_cancelled()
        except asyncio.CancelledError as exc:
            cancellation = exc
        return Settled(value, cancellation)

    async def run(self, fn: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
        settled = await self.settle(fn, *args, **kwargs)
        if settled.cancellation is not None:
            # AnyIO recognizes its scope marker on the original exception.
            raise settled.cancellation
        return settled.value

    async def aclose(self) -> None:
        self._closed = True
        deadline = monotonic() + self.seconds
        cancellation = None
        with CancelScope(shield=True):
            while self._pending:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise GuardrailError(ErrorCode.AUDIT_INTEGRITY)
                try:
                    await asyncio.wait(set(self._pending), timeout=remaining)
                except asyncio.CancelledError as exc:
                    cancellation = exc
        if cancellation is not None:
            raise cancellation
