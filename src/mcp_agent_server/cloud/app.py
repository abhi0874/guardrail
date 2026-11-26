"""Bounded, authenticated demo API; never an MCP or approval proxy."""

import asyncio
import ipaddress
import json
import re
from uuid import UUID, uuid4

from mcp import MCPError
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import Receive, Scope, Send

from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.rate_limiting import RateLimiter
from mcp_agent_server.guardrails.security_settings import RateSettings
from mcp_agent_server.tools.registry import SPECS

from .broker import Broker, DeniedKeyConflict
from .settings import CloudSettings
from .storage import Sessions, digest

OPERATIONS = frozenset({"health", "search_documents", "read_document", "write_note"})


def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def failure_code(exc: BaseException) -> ErrorCode | None:
    if isinstance(exc, DeniedKeyConflict):
        return ErrorCode.IDEMPOTENCY_KEY_CONFLICT
    if isinstance(exc, MCPError) and isinstance(exc.data, dict):
        try:
            raw = exc.data.get("code")
            if raw == ErrorCode.IDEMPOTENCY_KEY_CONFLICT:
                return None  # Only a conflict observed at call_tool establishes denial.
            return ErrorCode(raw) if isinstance(raw, str) else None
        except ValueError:
            return None
    if isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
        return failure_code(exc.exceptions[0])
    return None


class CloudApplication:
    def __init__(self, config: CloudSettings, sessions: Sessions, broker: Broker):
        self.config, self.sessions, self.broker = config, sessions, broker
        self.grants = {digest(c.token.get_secret_value()): c.identifier for c in config.clients}
        self.ready = False
        self.active = 0
        self.public_limit = RateLimiter(
            RateSettings(
                connection_capacity=120, global_capacity=120, connection_refill=2, global_refill=2
            )
        )
        self.client_limit = RateLimiter(
            RateSettings(
                connection_capacity=30, global_capacity=120, connection_refill=0.5, global_refill=2
            )
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        request = Request(scope, receive)
        correlation = uuid4().hex
        response: Response
        counted = False
        try:
            await self.public_limit.admit(UUID(int=0))
            if self.active >= 8:
                raise GuardrailError(ErrorCode.RATE_LIMIT_EXCEEDED)
            self.active += 1
            counted = True
            async with asyncio.timeout(4):
                response = await self.handle(request, correlation)
        except GuardrailError as exc:
            status = 429 if exc.public.code == ErrorCode.RATE_LIMIT_EXCEEDED else 503
            response = JSONResponse(
                {
                    "error": "rate_limited" if status == 429 else "unavailable",
                    "request_id": correlation,
                },
                status_code=status,
            )
        except (Exception, asyncio.CancelledError) as exc:
            # Cancellation never authorizes retry. Keep all exception details private.
            if isinstance(exc, asyncio.CancelledError):
                raise
            code = failure_code(exc)
            outcome = "unknown" if request.url.path.endswith("write_note") else "unavailable"
            if code == ErrorCode.IDEMPOTENCY_KEY_CONFLICT:
                outcome = "denied"
            response = JSONResponse(
                {
                    "error": code.value if code else "outcome_unknown",
                    "outcome": outcome,
                    "request_id": correlation,
                },
                status_code=409
                if code in (ErrorCode.IDEMPOTENCY_KEY_CONFLICT, ErrorCode.OPERATION_IN_PROGRESS)
                else 503,
            )
        finally:
            if counted:
                self.active -= 1
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "X-Request-ID": correlation,
            }
        )
        origin = request.headers.get("origin")
        if origin in self.config.origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
        await response(scope, receive, send)

    def secure_transport(self, request: Request) -> bool:
        """The original strict proxy mode retains its existing transport contract."""
        if request.url.scheme == "https":
            return True
        peer = request.scope.get("client")
        return bool(
            peer
            and any(
                ipaddress.ip_address(peer[0]) in ipaddress.ip_network(n)
                for n in self.config.trusted_proxies
            )
            and request.headers.get("x-forwarded-proto") == "https"
        )

    async def handle(self, request: Request, correlation: str) -> Response:
        # Constant, non-diagnostic probes perform no per-request SQL or tool work.
        if request.method == "GET" and request.url.path in ("/livez", "/readyz"):
            ready = request.url.path == "/livez" or self.ready
            return JSONResponse(
                {"status": "ok" if ready else "unavailable"}, status_code=200 if ready else 503
            )
        sensitive = {
            b"host",
            b"origin",
            b"authorization",
            b"x-forwarded-proto",
            b"content-length",
            b"idempotency-key",
        }
        names = [k.lower() for k, _ in request.scope["headers"] if k.lower() in sensitive]
        if len(names) != len(set(names)):
            return JSONResponse({"error": "invalid_headers"}, status_code=400)
        if request.headers.get("host") not in self.config.hosts:
            return JSONResponse({"error": "host_denied"}, status_code=400)
        if not self.secure_transport(request):
            return JSONResponse({"error": "https_required"}, status_code=400)
        origin = request.headers.get("origin")
        if origin is not None and origin not in self.config.origins:
            return JSONResponse({"error": "origin_denied"}, status_code=403)
        if request.method == "OPTIONS":
            if origin is None:
                return JSONResponse({"error": "origin_required"}, status_code=403)
            return Response(
                status_code=204,
                headers={
                    "Access-Control-Allow-Methods": "POST",
                    "Access-Control-Allow-Headers": "Authorization, Content-Type, Idempotency-Key",
                    "Access-Control-Max-Age": "300",
                },
            )
        operation = request.url.path.removeprefix("/api/v1/")
        if request.url.path != "/api/v1/" + operation or operation not in OPERATIONS:
            return JSONResponse({"error": "not_found"}, status_code=404)
        if request.method != "POST":
            return JSONResponse({"error": "method_denied"}, status_code=405)
        credential = request.headers.get("authorization", "")
        identity = (
            self.grants.get(digest(credential[7:]))
            if credential.startswith("Bearer ") and len(credential) <= 135
            else None
        )
        if identity is None:
            return JSONResponse({"error": "authentication_required"}, status_code=401)
        await self.client_limit.admit(identity)
        if not self.ready:
            return JSONResponse({"error": "unavailable"}, status_code=503)
        if request.headers.get("content-type") != "application/json":
            return JSONResponse({"error": "json_required"}, status_code=415)
        raw = bytearray()
        async for part in request.stream():
            if len(raw) + len(part) > 8192:
                return JSONResponse({"error": "body_too_large"}, status_code=413)
            raw.extend(part)
        try:
            args = json.loads(raw, object_pairs_hook=pairs)
            validated = SPECS[operation].arguments.model_validate(args, strict=True)
            key = request.headers.get("idempotency-key")
            if operation == "write_note":
                if key is None or re.fullmatch(r"[A-Za-z0-9_-]{1,96}", key) is None:
                    raise ValueError("Write key required")
            elif key is not None:
                raise ValueError("Unexpected key")
        except (ValueError, ValidationError, RecursionError):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        await self.sessions.persistence.run(self.sessions.touch, identity, digest(credential[7:]))
        value = await self.broker.call(identity, operation, validated.model_dump(mode="json"), key)
        return JSONResponse(
            {
                "request_id": correlation,
                "outcome": "confirmed",
                "result": value["result"],
                "replayed": value["replayed"],
            }
        )
