"""The pinned SDK invokes this boundary on decoded requests before parameter validation."""

from collections.abc import Callable
from dataclasses import replace
from typing import Any
from uuid import uuid4

from mcp import MCPError
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import BaseModel

from mcp_agent_server.errors import ErrorCode, GuardrailError

from .authorization import LOCAL, AuthorizationContext
from .models import GuardrailRequest
from .pipeline import Pipeline


class ToolMiddleware:
    def __init__(
        self,
        pipeline: Pipeline,
        *,
        http_context: Callable[[object], AuthorizationContext] | None = None,
        server_info: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        if pipeline.mutations and server_info is None:
            raise ValueError("Mutation middleware requires the current server info stamp")
        self.http_context = http_context
        self.server_info = server_info
        self.pipeline = pipeline
        # One server instance serves one stdio connection. This UUID identifies no principal.
        self.connection_id = uuid4()

    async def __call__(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        if ctx.method != "tools/call" or ctx.request_id is None:
            return await call_next(ctx)
        trusted = AuthorizationContext(identity=LOCAL, connection_id=self.connection_id)
        if self.http_context is not None:
            try:
                trusted = self.http_context(ctx.request)
            except ValueError:
                raise MCPError(code=-32000, message="Local client context unavailable") from None
        params = ctx.params or {}
        request = GuardrailRequest(
            connection_id=trusted.connection_id,
            transport="streamable-http" if self.http_context else "stdio",
            tool_name=params.get("name"),
            arguments=params.get("arguments", {}),
        )

        async def dispatch(validated: BaseModel) -> HandlerResult:
            result = await call_next(
                replace(ctx, params={**params, "arguments": validated.model_dump(mode="json")})
            )
            # SDK 2.3 serializes the inner handler result before returning through middleware.
            if not isinstance(result, dict) or result.get("isError", False):
                raise GuardrailError(ErrorCode.TOOL_EXECUTION_FAILED)
            return result

        meta = params.get("_meta")
        key = meta.get("mcp-agent-server/idempotency-key") if isinstance(meta, dict) else None
        modern = ctx.protocol_version in MODERN_PROTOCOL_VERSIONS

        def render(tool: str, data: object, replay: bool | None) -> dict[str, object]:
            return self.pipeline.outputs.render(
                tool,
                data,
                replay,
                self.server_info() if modern and self.server_info else None,
                modern,
            )

        execution, result = await self.pipeline.execute(
            request, dispatch, identity=trusted.identity, idempotency_key=key, render=render
        )
        if execution.error is not None:
            err = execution.error
            raise MCPError(
                code=-32602 if err.code == ErrorCode.INVALID_TOOL_ARGUMENTS else -32000,
                message=err.message,
                data={**err.model_dump(mode="json"), "request_id": str(request.request_id)},
            )
        return result
