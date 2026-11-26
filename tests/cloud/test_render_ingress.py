"""Header-independent ingress: real SDK/SQL effects and local TLS reverse proxy."""

import asyncio
import inspect
import json
import socket
import ssl
import subprocess
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from cloud.conftest import cloud_app as original_app
from cloud.conftest import cloud_config as original_config
from cloud.test_ingress import HEADERS
from mcp_agent_server.cloud.app import CloudApplication
from mcp_agent_server.cloud.render_ingress import RenderIngress, RenderSettings
from mcp_agent_server.cloud.runtime import PrivateServer, application, configuration
from mcp_agent_server.cloud.settings import CloudSettings
from mcp_agent_server.config import Settings
from mcp_agent_server.guardrails.rate_limiting import RateLimiter


@pytest.fixture
def cloud_config() -> RenderSettings:
    old = inspect.unwrap(original_config)()
    return RenderSettings(
        hosts=old.hosts, origins=old.origins, clients=old.clients, edge_https=True
    )


def api(app: CloudApplication, **kw: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.0.2.44", 1234)),
        base_url="http://demo.example.test",
        headers=HEADERS,
        **kw,
    )


@asynccontextmanager
async def serve(app: ASGIApp, **options: Any) -> AsyncIterator[str]:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server = PrivateServer(
            uvicorn.Config(
                app,
                proxy_headers=False,
                log_config=None,
                access_log=False,
                lifespan="off",
                **options,
            )
        )
        task = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            async with asyncio.timeout(5):
                while not server.started:
                    if task.done():
                        await task
                    await asyncio.sleep(0.01)
            yield f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 8)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "evil.test",
        },
        {"Forwarded": 'for=admin;proto=https;host="evil.test"'},
        {
            "X-Forwarded-For": "admin",
            "X-Forwarded-Proto": "http",
            "X-Forwarded-User": "administrator",
        },
        {"CF-Connecting-IP": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
    ],
)
async def test_forged_metadata_is_inert(
    cloud_app: CloudApplication, headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert isinstance(cloud_app, RenderIngress)
    original = cloud_app.handle
    seen: list[Scope] = []

    async def handle(request: Request, correlation: str) -> Response:
        seen.append(request.scope)
        return await original(request, correlation)

    monkeypatch.setattr(cloud_app, "handle", handle)
    async with api(cloud_app) as client:
        result = await client.post("/api/v1/health", json={}, headers=headers)
        assert result.status_code == 200 and result.json()["result"]["status"] == "ok"
    assert seen[0]["scheme"] == "http" and seen[0]["client"] == ("192.0.2.44", 1234)
    assert not any(
        k.lower().startswith(b"x-forwarded-")
        or k.lower() in (b"forwarded", b"cf-connecting-ip", b"x-real-ip")
        for k, _ in seen[0]["headers"]
    )
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone()[0] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/health",
        "/api/v1/write_note",
        "/mcp",
        "/api/v1/send_message",
        "/api/v1/fetch_url",
        "/api/v1/approve",
        "/api/v1/credentials",
    ],
)
async def test_anonymous_and_privileged_routes(cloud_app: CloudApplication, path: str) -> None:
    async with api(cloud_app) as client:
        result = await client.post(
            path,
            json={},
            headers={
                "Authorization": "",
                "Cookie": "authorization=" + "A" * 43,
                "Forwarded": "for=operator;proto=https",
            },
        )
        assert result.status_code == (
            401 if path in ("/api/v1/health", "/api/v1/write_note") else 404
        )
        assert "A" * 43 not in result.text and "set-cookie" not in result.headers
    with cloud_app.sessions.store.transaction() as db:
        for table in ("notes", "approvals", "operations", "simulations", "audit_events"):
            assert db.execute("SELECT count(*) FROM " + table).fetchone()[0] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers,code",
    [
        ({"Host": "evil.test", "X-Forwarded-Host": "demo.example.test"}, 400),
        ({"Origin": "https://evil.test", "Forwarded": "proto=https;host=demo.example.test"}, 403),
        ({"Origin": "null"}, 403),
        ({"Host": "demo.example.test,evil.test"}, 400),
    ],
)
async def test_real_host_origin_required(
    cloud_app: CloudApplication, headers: dict[str, str], code: int
) -> None:
    async with api(cloud_app) as client:
        result = await client.post(
            "/api/v1/write_note",
            json={"title": "synthetic", "body": "denied"},
            headers={"Idempotency-Key": "invalid-origin", **headers},
        )
        assert result.status_code == code
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_json_bearer_contract_and_strict_arguments(cloud_app: CloudApplication) -> None:
    async with api(cloud_app) as client:
        preflight = await client.options(
            "/api/v1/write_note",
            headers={
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type,idempotency-key",
            },
        )
        assert (
            preflight.status_code == 204
            and preflight.headers["access-control-allow-origin"] == "https://demo.example.test"
        )
        assert "access-control-allow-credentials" not in preflight.headers
        form = await client.post(
            "/api/v1/write_note",
            content="title=synthetic&body=test",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Idempotency-Key": "form",
            },
        )
        assert form.status_code == 415
        assert (await client.get("/api/v1/write_note")).status_code == 405
        forged = await client.post(
            "/api/v1/write_note",
            json={"title": "synthetic", "body": "test", "approved": True, "identity": "admin"},
            headers={"Idempotency-Key": "forged"},
        )
        assert forged.status_code == 400
        huge = await client.post(
            "/api/v1/write_note", content=b"x" * 8193, headers={"Idempotency-Key": "large"}
        )
        assert huge.status_code == 413
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_per_grant_and_global_quota_not_ip(cloud_app: CloudApplication) -> None:
    cloud_app.public_limit = RateLimiter(cloud_app.public_limit.settings, clock=lambda: 10)
    cloud_app.client_limit = RateLimiter(cloud_app.client_limit.settings, clock=lambda: 10)
    async with api(cloud_app) as client:
        for i in range(30):
            result = await client.post(
                "/api/v1/health", json={}, headers={"X-Forwarded-For": f"192.0.2.{i}"}
            )
            assert result.status_code == 200
        assert (await client.post("/api/v1/health", json={})).status_code == 429
        assert (
            await client.post(
                "/api/v1/health", json={}, headers={"Authorization": "Bearer " + "B" * 43}
            )
        ).status_code == 200
    settings = cloud_app.public_limit.settings.model_copy(
        update={"connection_capacity": 1, "global_capacity": 1}
    )
    cloud_app.public_limit = RateLimiter(settings, clock=lambda: 10)
    async with api(cloud_app) as client:
        assert (
            await client.post(
                "/api/v1/health", json={}, headers={"Authorization": "Bearer " + "B" * 43}
            )
        ).status_code == 200
        assert (
            await client.post(
                "/api/v1/health",
                json={},
                headers={"Authorization": "Bearer " + "B" * 43, "X-Forwarded-For": "different"},
            )
        ).status_code == 429
    assert cloud_app.active == 0


@pytest.mark.asyncio
async def test_lost_response_is_unknown_not_reexecuted(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = cloud_app.broker.call
    calls = 0

    async def lost(*args: Any, **kwargs: Any) -> dict[str, object]:
        nonlocal calls
        calls += 1
        await original(*args, **kwargs)
        raise TimeoutError("SYNTHETIC-PRIVATE-ERROR")

    monkeypatch.setattr(cloud_app.broker, "call", lost)
    async with api(cloud_app) as client:
        response = await client.post(
            "/api/v1/write_note",
            json={"title": "lost", "body": "synthetic"},
            headers={"Idempotency-Key": "lost"},
        )
        assert response.status_code == 503 and response.json()["outcome"] == "unknown"
        assert calls == 1 and "SYNTHETIC-PRIVATE-ERROR" not in response.text
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert (
            db.execute("SELECT count(*) FROM operations WHERE state='COMPLETED'").fetchone()[0] == 1
        )
    monkeypatch.setattr(cloud_app.broker, "call", original)
    async with api(cloud_app) as client:
        response = await client.post(
            "/api/v1/write_note",
            json={"title": "lost", "body": "synthetic"},
            headers={"Idempotency-Key": "lost"},
        )
        assert response.status_code == 200 and response.json()["replayed"] is True
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1


@pytest.mark.asyncio
async def test_cancelled_committed_write_preserves_durability(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    committed = asyncio.Event()
    original = cloud_app.broker.call

    async def suspended(*args: Any, **kwargs: Any) -> dict[str, object]:
        await original(*args, **kwargs)
        committed.set()
        await asyncio.Event().wait()
        raise AssertionError

    monkeypatch.setattr(cloud_app.broker, "call", suspended)
    async with api(cloud_app) as client:
        task = asyncio.create_task(
            client.post(
                "/api/v1/write_note",
                json={"title": "cancelled", "body": "synthetic"},
                headers={"Idempotency-Key": "cancelled"},
            )
        )
        async with asyncio.timeout(5):
            await committed.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    assert cloud_app.active == 0 and not cloud_app.broker.clients._entries
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone()[0] == 1
    monkeypatch.setattr(cloud_app.broker, "call", original)
    async with api(cloud_app) as client:
        result = await client.post(
            "/api/v1/write_note",
            json={"title": "cancelled", "body": "synthetic"},
            headers={"Idempotency-Key": "cancelled"},
        )
        assert result.status_code == 200 and result.json()["replayed"] is True


@pytest.mark.asyncio
async def test_restart_replay_and_cross_client_isolation(
    postgres: dict[str, str], pg_settings: Settings, cloud_config: RenderSettings
) -> None:
    factory = inspect.unwrap(original_app)
    gen = factory(postgres, pg_settings, cloud_config)
    app = await anext(gen)
    try:
        async with api(app) as client:
            r = await client.post(
                "/api/v1/write_note",
                json={"title": "persisted", "body": "synthetic"},
                headers={"Idempotency-Key": "restart"},
            )
            assert r.status_code == 200
            receipt = r.json()["result"]
        with app.sessions.store.transaction() as db:
            created = db.execute(
                "SELECT created FROM mcp_cloud.sessions WHERE session_id=?",
                (str(cloud_config.clients[0].identifier),),
            ).fetchone()[0]
    finally:
        await gen.aclose()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    settings = pg_settings.model_copy(
        update={"http": pg_settings.http.model_copy(update={"enabled": True, "port": port})}
    )
    async with application(settings, cloud_config) as restarted:
        assert isinstance(restarted, RenderIngress)
        async with api(restarted) as client:
            same = await client.post(
                "/api/v1/write_note",
                json={"title": "persisted", "body": "synthetic"},
                headers={"Idempotency-Key": "restart"},
            )
            assert (
                same.status_code == 200
                and same.json()["replayed"] is True
                and same.json()["result"] == receipt
            )
            other = await client.post(
                "/api/v1/write_note",
                json={"title": "persisted", "body": "synthetic"},
                headers={
                    "Idempotency-Key": "restart",
                    "Authorization": "Bearer " + "B" * 43,
                    "X-Forwarded-User": str(cloud_config.clients[0].identifier),
                },
            )
            assert other.status_code == 409
        with restarted.sessions.store.transaction() as db:
            assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
            assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == 1
            assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
            assert (
                db.execute(
                    "SELECT created FROM mcp_cloud.sessions WHERE session_id=?",
                    (str(cloud_config.clients[0].identifier),),
                ).fetchone()[0]
                == created
            )


@pytest.mark.asyncio
async def test_real_tls_proxy_and_secret_boundaries(
    cloud_app: CloudApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    cert, key = tmp_path / "ca.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    original = cloud_app.broker.clients.issue
    capabilities = []

    def issued(*args: Any, **kwargs: Any) -> Any:
        token, reference = original(*args, **kwargs)
        capabilities.append(token.get_secret_value())
        return token, reference

    monkeypatch.setattr(cloud_app.broker.clients, "issue", issued)
    async with serve(cloud_app) as backend:
        async with httpx.AsyncClient(trust_env=False) as upstream:

            async def proxy(scope: Scope, receive: Receive, send: Send) -> None:
                request = Request(scope, receive)
                headers = [
                    (k, v)
                    for k, v in request.headers.raw
                    if k.lower() not in (b"host", b"content-length")
                ]
                headers += [
                    (b"host", b"demo.example.test"),
                    (b"x-forwarded-proto", b"http"),
                    (b"forwarded", b"for=admin;proto=https;host=evil.test"),
                ]
                result = await upstream.request(
                    request.method,
                    backend + request.url.path,
                    headers=headers,
                    content=await request.body(),
                )
                await Response(
                    result.content, status_code=result.status_code, media_type="application/json"
                )(scope, receive, send)

            async with serve(proxy, ssl_certfile=str(cert), ssl_keyfile=str(key)) as front:
                async with httpx.AsyncClient(
                    verify=ssl.create_default_context(cafile=str(cert)),
                    trust_env=False,
                    headers=HEADERS,
                ) as client:
                    response = await client.post(
                        front.replace("http:", "https:") + "/api/v1/health",
                        json={},
                        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.test"},
                    )
                    assert (
                        response.status_code == 200 and response.json()["result"]["status"] == "ok"
                    )
    assert capabilities and not cloud_app.broker.clients._entries
    for secret in ["A" * 43, "B" * 43, *capabilities]:
        assert secret not in response.text + caplog.text
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone()[0] == 1


def environment(config: RenderSettings) -> dict[str, str]:
    return {
        "MCP_CLOUD_INGRESS_MODE": "render_edge",
        "MCP_CLOUD_RENDER_EDGE_HTTPS": "true",
        "MCP_CLOUD_HOSTS": "demo.example.test",
        "MCP_CLOUD_ORIGINS": "https://demo.example.test",
        "MCP_CLOUD_CLIENTS": json.dumps(
            [
                {"identifier": str(c.identifier), "token": c.token.get_secret_value()}
                for c in config.clients
            ]
        ),
    }


@pytest.mark.parametrize(
    "change",
    [
        {"MCP_CLOUD_RENDER_EDGE_HTTPS": "false"},
        {"MCP_CLOUD_RENDER_EDGE_HTTPS": ""},
        {"MCP_CLOUD_TRUSTED_PROXIES": "127.0.0.1/32"},
        {"MCP_CLOUD_INGRESS_MODE": "unknown"},
        {"MCP_CLOUD_HOSTS": "*"},
    ],
)
def test_explicit_safe_configuration(cloud_config: RenderSettings, change: dict[str, str]) -> None:
    with pytest.raises((ValidationError, ValueError)):
        configuration({**environment(cloud_config), **change})


def test_opt_in_and_original_mode_preserved(cloud_config: RenderSettings) -> None:
    env = environment(cloud_config)
    assert isinstance(configuration(env), RenderSettings)
    env.pop("MCP_CLOUD_INGRESS_MODE")
    env["MCP_CLOUD_TRUSTED_PROXIES"] = "127.0.0.1/32"
    assert type(configuration(env)) is CloudSettings
    assert "A" * 43 not in repr(cloud_config) + cloud_config.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["/mcp", "/api/v1/send_message", "/api/v1/fetch_url", "/api/v1/approve", "/api/v1/credentials"],
)
async def test_authenticated_private_surface_stays_hidden(
    cloud_app: CloudApplication, path: str
) -> None:
    async with api(cloud_app) as client:
        response = await client.post(path, json={"approved": True, "tool": "send_message"})
        assert response.status_code == 404 and "result" not in response.json()
    with cloud_app.sessions.store.transaction() as db:
        for table in ("notes", "approvals", "simulations", "operations", "audit_events"):
            assert db.execute("SELECT count(*) FROM " + table).fetchone()[0] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["Host", "Origin"])
async def test_duplicate_authority_headers_fail(cloud_app: CloudApplication, name: str) -> None:
    value = "demo.example.test" if name == "Host" else "https://demo.example.test"
    async with api(cloud_app) as client:
        response = await client.post(
            "/api/v1/health", json={}, headers=[(name, value), (name, value)]
        )
        assert response.status_code == 400
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 0


def test_constructor_rejects_unacknowledged_copy(cloud_config: RenderSettings) -> None:
    # Validate before retaining or touching injected storage/client objects.
    from unittest.mock import Mock

    with pytest.raises(ValueError, match="acknowledgement"):
        RenderIngress(cloud_config.model_copy(update={"edge_https": False}), Mock(), Mock())
