"""Limit SDK method-not-found details without taking over wire serialization."""

from typing import Any

from mcp import MCPError
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp_types import METHOD_NOT_FOUND


async def safe_protocol_errors(
    ctx: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    try:
        return await call_next(ctx)
    except MCPError as error:
        if ctx.method == "tools/call" or error.code != METHOD_NOT_FOUND:
            raise
        # Drop the entire data value, including any nested values. The SDK owns
        # the request ID, JSON-RPC envelope, HTTP status and streaming framing.
        raise MCPError(code=METHOD_NOT_FOUND, message="Method not found") from None
