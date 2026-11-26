import asyncio
import json
from typing import Any
from uuid import uuid4

import httpx
import pytest
from mcp import MCPError
from pydantic import SecretStr, ValidationError

from mcp_agent_server.cloud.app import CloudApplication, failure_code
from mcp_agent_server.cloud.settings import ClientGrant, CloudSettings
from mcp_agent_server.errors import ErrorCode

HEADERS = {
    "Authorization": "Bearer " + "A" * 43,
    "Content-Type": "application/json",
    "Origin": "https://demo.example.test",
}


def client(
    app: CloudApplication, *, scheme: str = "https", peer: str = "127.0.0.1"
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(peer, 12345)),
        base_url=scheme + "://demo.example.test",
        headers=HEADERS,
    )


@pytest.mark.asyncio
async def test_real_broker_notes_isolation_and_records(cloud_app: CloudApplication) -> None:
    async with client(cloud_app) as api:
        assert (await api.get("/livez")).status_code == 200
        assert (await api.get("/readyz")).status_code == 200
        for name, args in [
            ("health", {}),
            ("search_documents", {"query": "approval"}),
            ("read_document", {"document_id": "approval-guide"}),
        ]:
            response = await api.post("/api/v1/" + name, json=args)
            assert response.status_code == 200 and response.json()["outcome"] == "confirmed"
        value = {"title": "Cloud synthetic", "body": "Private per client"}
        first = await api.post(
            "/api/v1/write_note", json=value, headers={"Idempotency-Key": "cloud-one"}
        )
        second = await api.post(
            "/api/v1/write_note", json=value, headers={"Idempotency-Key": "cloud-one"}
        )
        assert first.status_code == second.status_code == 200
        assert (
            first.json()["result"] == second.json()["result"] and second.json()["replayed"] is True
        )
        other = await api.post(
            "/api/v1/write_note",
            json=value,
            headers={"Idempotency-Key": "cloud-one", "Authorization": "Bearer " + "B" * 43},
        )
        assert other.status_code == 409 and other.json()["error"] == "idempotency_key_conflict"
        assert "A" * 43 not in first.text + second.text + other.text
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM mcp_cloud.sessions").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone()[0] == 4
    assert not cloud_app.broker.clients._entries


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/mcp",
        "/docs",
        "/admin",
        "/api/v1/send_message",
        "/api/v1/fetch_url",
        "/api/v1/approve",
        "/api/v1/sessions",
    ],
)
async def test_privileged_surface_not_exposed(cloud_app: CloudApplication, path: str) -> None:
    async with client(cloud_app) as api:
        assert (await api.post(path, json={})).status_code == 404
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [
        "auth",
        "host",
        "origin",
        "proxy",
        "key",
        "extra",
        "malformed",
        "duplicate-json",
        "oversize",
        "type",
        "method",
        "duplicate-header",
        "read-key",
        "not-ready",
    ],
)
async def test_ingress_fail_closed(cloud_app: CloudApplication, kind: str) -> None:
    kwargs: dict[str, Any] = {"json": {}}
    path = "/api/v1/health"
    headers = httpx.Headers()
    method = "POST"
    if kind == "auth":
        headers["Authorization"] = "Bearer wrong"
    if kind == "host":
        headers["Host"] = "evil.test"
    if kind == "origin":
        headers["Origin"] = "https://evil.test"
    if kind == "proxy":
        headers["X-Forwarded-Proto"] = "https"
    if kind == "key":
        path = "/api/v1/write_note"
        kwargs = {"json": {"title": "x", "body": "y"}}
    if kind == "extra":
        kwargs = {"json": {"approved": True, "identity": "operator"}}
    if kind == "malformed":
        kwargs = {"content": b"{"}
    if kind == "duplicate-json":
        kwargs = {"content": b'{"x":1,"x":2}'}
    if kind == "oversize":
        kwargs = {"content": b"x" * 8193}
    if kind == "type":
        headers["Content-Type"] = "text/plain"
    if kind == "method":
        method = "GET"
        kwargs = {}
    if kind == "duplicate-header":
        headers = httpx.Headers([("Host", "demo.example.test"), ("Host", "evil.test")])
    if kind == "read-key":
        headers["Idempotency-Key"] = "unexpected"
    if kind == "not-ready":
        cloud_app.ready = False
    async with client(
        cloud_app,
        scheme="http" if kind == "proxy" else "https",
        peer="192.0.2.1" if kind == "proxy" else "127.0.0.1",
    ) as api:
        response = await api.request(method, path, headers=headers, **kwargs)
        assert response.status_code in (400, 401, 403, 405, 413, 415, 503)
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_preflight_proxy_and_capacity(cloud_app: CloudApplication) -> None:
    async with client(cloud_app, scheme="http") as api:
        r = await api.options("/api/v1/health", headers={"X-Forwarded-Proto": "https"})
        assert (
            r.status_code == 204
            and r.headers["Access-Control-Allow-Origin"] == "https://demo.example.test"
        )
        r = await api.post(
            "/api/v1/health",
            json={},
            headers={"X-Forwarded-Proto": "https", "X-Forwarded-User": "operator"},
        )
        assert r.status_code == 200
        cloud_app.active = 8
        assert (await api.post("/api/v1/health", json={})).status_code == 429
        cloud_app.active = 0
        cloud_app.ready = False
        assert (await api.get("/readyz")).status_code == 503


@pytest.mark.asyncio
async def test_timeouts_safe_unknown_no_automatic_retry(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    async def lost(*args: Any) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise TimeoutError("synthetic credential must stay private")

    monkeypatch.setattr(cloud_app.broker, "call", lost)
    async with client(cloud_app) as api:
        response = await api.post(
            "/api/v1/write_note",
            json={"title": "Synthetic", "body": "Unknown"},
            headers={"Idempotency-Key": "lost"},
        )
        assert response.status_code == 503 and response.json()["outcome"] == "unknown"
        assert "synthetic credential" not in response.text and calls == 1
    assert cloud_app.active == 0


@pytest.mark.asyncio
async def test_request_deadline_and_cancellation(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered = asyncio.Event()

    async def wait(*args: Any) -> dict[str, object]:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError

    monkeypatch.setattr(cloud_app.broker, "call", wait)
    async with client(cloud_app) as api:
        task = asyncio.create_task(api.post("/api/v1/health", json={}))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert cloud_app.active == 0


def test_error_projection() -> None:
    error = MCPError(code=-32000, message="private", data={"code": "operation_in_progress"})
    assert failure_code(ExceptionGroup("wrapper", [error])) == ErrorCode.OPERATION_IN_PROGRESS
    assert failure_code(MCPError(code=-1, message="private", data={"code": "not-real"})) is None
    assert failure_code(ValueError("secret")) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("hosts", ("evil/host",)),
        ("origins", ("http://demo.test",)),
        ("trusted_proxies", ("0.0.0.0/0",)),
        ("clients", ()),
        ("port", 80),
    ],
)
def test_config_rejects_insecure(cloud_config: CloudSettings, field: str, value: Any) -> None:
    data = {
        "hosts": cloud_config.hosts,
        "origins": cloud_config.origins,
        "trusted_proxies": cloud_config.trusted_proxies,
        "clients": cloud_config.clients,
        field: value,
    }
    with pytest.raises(ValidationError):
        CloudSettings.model_validate(data)


def test_env_and_credentials(cloud_config: CloudSettings) -> None:
    with pytest.raises(ValidationError):
        ClientGrant(identifier=uuid4(), token=SecretStr("weak"))
    with pytest.raises(ValidationError):
        CloudSettings(
            hosts=cloud_config.hosts,
            origins=cloud_config.origins,
            trusted_proxies=cloud_config.trusted_proxies,
            clients=(cloud_config.clients[0], cloud_config.clients[0]),
        )
    env = {
        "MCP_CLOUD_HOSTS": "demo.example.test",
        "MCP_CLOUD_ORIGINS": "https://demo.example.test",
        "MCP_CLOUD_TRUSTED_PROXIES": "127.0.0.1/32",
        "MCP_CLOUD_CLIENTS": json.dumps([{"identifier": str(uuid4()), "token": "Z" * 43}]),
    }
    cfg = CloudSettings.from_env(env)
    assert cfg.port == 10000 and "Z" * 43 not in repr(cfg) + cfg.model_dump_json()
