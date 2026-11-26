"""Recognize timeout signals without inspecting or retaining exception text."""

import httpx
import httpx2
from mcp import MCPError
from mcp_types import REQUEST_TIMEOUT


def request_timed_out(error: BaseException) -> bool:
    pending = [error]
    seen: set[int] = set()
    while pending:
        exc = pending.pop()
        if id(exc) in seen:
            continue
        seen.add(id(exc))
        if isinstance(exc, (TimeoutError, httpx.TimeoutException, httpx2.TimeoutException)):
            return True
        if isinstance(exc, MCPError) and (
            exc.code == REQUEST_TIMEOUT
            or (isinstance(exc.data, dict) and exc.data.get("code") == "fetch_timeout")
        ):
            return True
        if isinstance(exc, BaseExceptionGroup):
            pending.extend(exc.exceptions)
        if exc.__cause__ is not None:
            pending.append(exc.__cause__)
        elif not exc.__suppress_context__ and exc.__context__ is not None:
            pending.append(exc.__context__)
    return False
