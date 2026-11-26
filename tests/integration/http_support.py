import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx2
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from pydantic import SecretStr

from mcp_agent_server.adapters.http import Fetcher
from mcp_agent_server.adapters.outbox import Outbox
from mcp_agent_server.config import Settings
from mcp_agent_server.server import create_server
from mcp_agent_server.transport.context import Clients
from mcp_agent_server.transport.http import HTTPApplication


@asynccontextmanager
async def listener(
    path: Path, *, fetcher: Fetcher | None = None, outbox: Outbox | None = None, **options: object
) -> AsyncIterator[tuple[str, Clients, Settings]]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    cfg = Settings.model_validate(
        {
            "audit_db": path,
            "http": {"enabled": True, "port": port},
            **options,
        }
    )
    clients = Clients(cfg.http)
    app = HTTPApplication(
        create_server(cfg, http_context=clients.resolve, fetcher=fetcher, outbox=outbox),
        cfg,
        clients,
    )
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_config=None,
            access_log=False,
            proxy_headers=False,
            timeout_graceful_shutdown=3,
        )
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        assert sock.getsockname()[0] == "127.0.0.1"
        yield f"http://127.0.0.1:{port}/mcp", clients, cfg
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 8)
        sock.close()
        assert not clients._entries


@asynccontextmanager
async def client(url: str, secret: SecretStr) -> AsyncIterator[Client]:
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + secret.get_secret_value()},
        trust_env=False,
    ) as http:
        async with Client(streamable_http_client(url, http_client=http)) as mcp:
            yield mcp
