import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.types import Receive, Scope, Send

from mcp_agent_server.cloud.app import CloudApplication
from mcp_agent_server.cloud.runtime import application, main
from mcp_agent_server.cloud.settings import CloudSettings
from mcp_agent_server.config import Settings


@pytest.mark.asyncio
async def test_real_public_tcp_listener(cloud_app: CloudApplication) -> None:
    import uvicorn

    from mcp_agent_server.cloud.runtime import PrivateServer

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server = PrivateServer(
            uvicorn.Config(
                cloud_app,
                host="127.0.0.1",
                port=port,
                proxy_headers=False,
                log_config=None,
                access_log=False,
                lifespan="off",
            )
        )
        task = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            async with asyncio.timeout(5):
                while not server.started:
                    await asyncio.sleep(0.01)
            async with httpx.AsyncClient(trust_env=False) as client:
                r = await client.post(
                    f"http://127.0.0.1:{port}/api/v1/health",
                    json={},
                    headers={
                        "Host": "demo.example.test",
                        "X-Forwarded-Proto": "https",
                        "Authorization": "Bearer " + "A" * 43,
                        "Content-Type": "application/json",
                    },
                )
                assert r.status_code == 200 and r.json()["result"]["status"] == "ok"
        finally:
            server.should_exit = True
            await task


def test_production_startup_listener_config(
    cloud_config: CloudSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcp_agent_server.cloud.runtime as runtime

    settings = Settings.model_construct(
        environment="production",
        database_url=__import__("pydantic").SecretStr(
            "postgresql://runtime:synthetic@db.example.test:5432/db?sslmode=verify-full"
        ),
        storage_backend="postgresql",
    )
    monkeypatch.setattr(Settings, "from_env", lambda: settings)
    monkeypatch.setattr(CloudSettings, "from_env", lambda env: cloud_config)
    seen = []

    async def fake_app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    @asynccontextmanager
    async def fake_application(*args: Any) -> AsyncIterator[Any]:
        yield fake_app

    monkeypatch.setattr(runtime, "application", fake_application)

    def run(app: Starlette, **kwargs: Any) -> None:
        assert (
            kwargs["host"] == "0.0.0.0"
            and kwargs["port"] == 10000
            and kwargs["proxy_headers"] is False
            and kwargs["limit_concurrency"] == 32
        )

        async def check() -> None:
            async with app.router.lifespan_context(app) as state:
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://test"
                ):
                    # Dispatch with explicitly installed lifespan state.
                    response = []
                    scope: Scope = {
                        "type": "http",
                        "method": "GET",
                        "path": "/livez",
                        "root_path": "",
                        "query_string": b"",
                        "headers": [],
                        "state": state,
                        "scheme": "http",
                        "server": ("test", 80),
                        "client": ("127.0.0.1", 1),
                        "http_version": "1.1",
                    }

                    async def receive() -> dict[str, object]:
                        return {"type": "http.request", "body": b""}

                    async def send(message: Any) -> None:
                        response.append(message)

                    await app(scope, receive, send)
                    assert response[0]["status"] == 200

        asyncio.run(check())
        seen.append(True)

    monkeypatch.setattr(__import__("uvicorn"), "run", run)
    assert main() == 0 and seen == [True]
    settings = settings.model_copy(
        update={
            "database_url": __import__("pydantic").SecretStr(
                "postgresql://runtime:synthetic@db.example.test:6543/db?sslmode=verify-full"
            )
        }
    )
    assert main() == 1


@pytest.mark.asyncio
async def test_missing_cloud_schema_startup_fails(
    pg_settings: Settings, cloud_config: CloudSettings, postgres: dict[str, str]
) -> None:
    import psycopg
    from psycopg.conninfo import make_conninfo

    from mcp_agent_server.errors import GuardrailError

    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
        db.execute("DROP SCHEMA IF EXISTS mcp_cloud CASCADE")
    # Runtime must not auto-migrate or fall back when required cloud tables are absent.
    with pytest.raises(GuardrailError):
        async with application(pg_settings, cloud_config):
            raise AssertionError
