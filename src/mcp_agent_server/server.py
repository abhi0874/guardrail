"""Construct the server on demand and serve guarded tools over stdio."""

import logging
import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from importlib.metadata import version

from mcp.server import MCPServer
from pydantic import ValidationError

from .adapters.http import Fetcher
from .adapters.outbox import Outbox
from .config import Settings, prepare_runtime
from .errors import ConfigurationError, ErrorCode, GuardrailError, InternalError
from .guardrails.authorization import AuthorizationContext
from .guardrails.middleware import ToolMiddleware
from .guardrails.output_filtering import OutputGuard
from .guardrails.pipeline import Pipeline
from .guardrails.policy import load_policy
from .guardrails.rate_limiting import process_limiter
from .logging import configure_logging
from .tools.models import Health as Health
from .tools.registry import SPECS, register


def create_server(
    settings: Settings,
    *,
    http_context: Callable[[object], AuthorizationContext] | None = None,
    health_handler: Callable[[], Health] | None = None,
    fetcher: Fetcher | None = None,
    outbox: Outbox | None = None,
) -> MCPServer[None]:
    prepare_runtime()
    package_version = version("guardrail-mcp-server")
    policy = load_policy(settings.policy_file)
    if any(
        rule.action == "permit"
        and rule.tool in SPECS
        and SPECS[rule.tool].requires_approval
        and not rule.approval_required
        for rule in policy.document.rules
    ):
        raise GuardrailError(ErrorCode.INVALID_POLICY)
    if fetcher is not None and fetcher.hosts != frozenset(settings.fetch_hosts):
        raise ConfigurationError()
    from .storage.factory import create_store

    store = create_store(settings)
    pipeline = Pipeline(
        store,
        {name: spec.arguments for name, spec in SPECS.items()},
        settings.max_argument_bytes,
        settings.max_argument_depth,
        policy=policy,
        mutations={name: spec.mutation for name, spec in SPECS.items() if spec.mutation},
        outputs=OutputGuard(settings.output, {name: spec.result for name, spec in SPECS.items()}),
        limiter=process_limiter(settings.rate),
        constraint_errors={"read_document": ErrorCode.DOCUMENT_NOT_FOUND},
    )

    @asynccontextmanager
    async def lifespan(_: MCPServer[None]) -> AsyncIterator[None]:
        try:
            yield None
        finally:
            try:
                await pipeline.persistence.aclose()
            finally:
                store.close()

    server: MCPServer[None] = MCPServer(
        settings.app_name,
        version=package_version,
        log_level=settings.log_level,
        lifespan=lifespan,
        middleware=[
            ToolMiddleware(
                pipeline,
                http_context=http_context,
                server_info=lambda: {"name": settings.app_name, "version": package_version},
            )
        ],
    )

    @server.tool(structured_output=True, annotations=SPECS["health"].annotations)
    async def health() -> Health:
        """Return this service's name, installed version and health status."""
        pipeline.claim("health")
        if health_handler is not None:
            return health_handler()
        return Health(service=settings.app_name, version=package_version)

    register(server, pipeline, fetcher or Fetcher(settings.fetch_hosts), outbox or Outbox())
    return server


def main() -> int:
    try:
        settings = Settings.from_env()
    except ValidationError as exc:
        error = ConfigurationError()
        # Only schema field names, never rejected environment values.
        fields = sorted(
            {
                str(issue["loc"][0]) if issue["loc"] else "storage"
                for issue in exc.errors(include_input=False)
            }
        )
        configure_logging("ERROR").error(
            "%s Fields: %s",
            error.public.message,
            ", ".join(fields),
            extra={"error_code": error.public.code},
        )
        return 2
    logger = configure_logging(settings.log_level)
    logging.basicConfig(level=settings.log_level, handlers=logger.handlers)
    try:
        if settings.http.enabled:
            from .transport.http import run_http

            run_http(settings)
            return 0
        server = create_server(settings)
        logger.info(
            "Starting MCP server",
            extra={"transport": settings.transport, "process_id": os.getpid()},
        )
        server.run(transport=settings.transport)
    except GuardrailError as failure:
        logger.error(failure.public.message, extra={"error_code": failure.public.code})
        return 1
    except Exception:
        internal = InternalError()
        logger.error(internal.public.message, extra={"error_code": internal.public.code})
        return 1
    return 0
