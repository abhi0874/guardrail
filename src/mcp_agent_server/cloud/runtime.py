"""Supervised public ingress and private MCP listeners, with no proxy auto-trust."""

import asyncio
import logging
import os
import socket
from collections.abc import AsyncIterator, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager

import uvicorn
from starlette.applications import Starlette

from mcp_agent_server.config import Settings
from mcp_agent_server.logging import configure_logging
from mcp_agent_server.server import create_server
from mcp_agent_server.storage.postgres import PostgresStore
from mcp_agent_server.transport.context import Clients
from mcp_agent_server.transport.http import HTTPApplication

from .app import CloudApplication
from .broker import Broker
from .render_ingress import RenderIngress, RenderSettings
from .settings import CloudSettings
from .storage import Sessions


class PrivateServer(uvicorn.Server):
    @contextmanager
    def capture_signals(self) -> Iterator[None]:
        # Only the public process owns SIGTERM. Its lifespan drains this listener.
        yield


@asynccontextmanager
async def application(settings: Settings, config: CloudSettings) -> AsyncIterator[CloudApplication]:
    if settings.storage_backend != "postgresql" or settings.http.port == config.port:
        raise ValueError("Separate listeners and PostgreSQL required")
    store = PostgresStore(settings)
    sessions = Sessions(store)
    clients = Clients(settings.http)
    task = None
    server = None
    sock = socket.socket()
    broker = Broker(f"http://127.0.0.1:{settings.http.port}/mcp", clients)
    app: CloudApplication
    if isinstance(config, RenderSettings):
        app = RenderIngress(config, sessions, broker)
    else:
        app = CloudApplication(config, sessions, broker)
    try:
        await sessions.persistence.run(sessions.register, config.clients)
        sock.bind(("127.0.0.1", settings.http.port))
        core = HTTPApplication(
            create_server(settings, http_context=clients.resolve), settings, clients
        )
        server = PrivateServer(
            uvicorn.Config(
                core,
                log_config=None,
                access_log=False,
                proxy_headers=False,
                server_header=False,
                timeout_graceful_shutdown=5,
            )
        )
        task = asyncio.create_task(server.serve(sockets=[sock]))
        async with asyncio.timeout(5):
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("Internal MCP listener stopped")
                await asyncio.sleep(0.01)
        app.ready = True

        async def heartbeat() -> None:
            while True:
                await asyncio.sleep(5)
                # Keep the last completed probe result while this probe is pending.
                try:

                    def check() -> None:
                        with store.transaction() as db:
                            db.execute("SELECT 1").fetchone()

                    await sessions.persistence.run(check)
                    app.ready = not task.done()
                except Exception:
                    app.ready = False  # Fail closed; never log storage exception data.

        health = asyncio.create_task(heartbeat())
        try:
            yield app
        finally:
            health.cancel()
            await asyncio.gather(health, return_exceptions=True)
    finally:
        app.ready = False
        if server is not None:
            server.should_exit = True
        try:
            if task is not None:
                await asyncio.wait_for(task, 8)
        finally:
            sock.close()
            clients.clear()
            try:
                await sessions.persistence.aclose()
            finally:
                store.close()


def configuration(env: Mapping[str, str]) -> CloudSettings:
    mode = env.get("MCP_CLOUD_INGRESS_MODE", "trusted_proxy")
    if mode == "render_edge":
        return RenderSettings.from_env(env)
    if mode != "trusted_proxy":
        raise ValueError("Explicit supported ingress mode required")
    return CloudSettings.from_env(env)


def main() -> int:
    logger = configure_logging("INFO")
    logging.basicConfig(level="INFO", handlers=logger.handlers)
    try:
        settings = Settings.from_env()
        config = configuration(os.environ)
        from mcp_agent_server.storage.settings import connection_parameters

        params = connection_parameters(settings.database_url, production=True)
        if params["port"] != "5432":
            raise ValueError("Only the verified session-pool configuration is enabled")
        if settings.environment != "production":
            raise ValueError("Production mode required")

        @asynccontextmanager
        async def lifespan(_: Starlette) -> AsyncIterator[dict[str, object]]:
            async with application(settings, config) as app:
                yield {"cloud_app": app}

        from starlette.types import Receive, Scope, Send

        async def dispatch(scope: Scope, receive: Receive, send: Send) -> None:
            await scope["state"]["cloud_app"](scope, receive, send)

        host = Starlette(lifespan=lifespan)
        host.mount("/", dispatch)
        uvicorn.run(
            host,
            host="0.0.0.0",
            port=config.port,
            proxy_headers=False,
            log_config=None,
            access_log=False,
            server_header=False,
            limit_concurrency=32,
            timeout_keep_alive=3,
            timeout_graceful_shutdown=8,
            h11_max_incomplete_event_size=16384,
            ws="none",
        )
    except Exception:
        logger.error("Cloud service failed safely; verify private configuration and storage")
        return 1
    return 0
