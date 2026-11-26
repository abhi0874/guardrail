"""Observe real PostgreSQL effects through the authenticated official MCP ingress."""

from typing import Any

import pytest
from mcp import Client

from cloud.test_ingress import client
from mcp_agent_server.cloud.app import CloudApplication


@pytest.mark.asyncio
async def test_committed_response_survives_transport_cleanup_failure(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    close = Client.__aexit__
    calls = 0

    async def broken_close(self: Client, *args: Any) -> None:
        nonlocal calls
        await close(self, *args)
        calls += 1
        raise OSError("synthetic cleanup error, private data")

    monkeypatch.setattr(Client, "__aexit__", broken_close)
    async with client(cloud_app) as api:
        response = await api.post(
            "/api/v1/write_note",
            json={"title": "Confirmed note", "body": "Synthetic content"},
            headers={"Idempotency-Key": "cleanup-failure"},
        )
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT state FROM operations").fetchone()[0] == "COMPLETED"
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events WHERE phase='post' AND status='succeeded'"
            ).fetchone()[0]
            == 1
        )
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
    assert calls == 1 and not cloud_app.broker.clients._entries
    assert response.status_code == 200, response.json()
    assert response.json()["result"] == {"note_id": 1, "persisted": True}


def durable(app: CloudApplication, notes: int, state: str | None, posts: int) -> None:
    with app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == notes
        rows = db.execute("SELECT state FROM operations").fetchall()
        assert [r[0] for r in rows] == ([] if state is None else [state])
        assert (
            db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone()[0]
            == posts
        )
        if state == "COMPLETED":
            assert (
                db.execute(
                    "SELECT count(*) FROM operations o JOIN audit_events p ON p.event_id=o.pre_id "
                    "JOIN audit_events z ON z.event_id=o.post_id "
                    "WHERE z.parent_event_id=p.event_id AND z.request_id=p.request_id "
                    "AND z.status='succeeded' AND z.error_code IS NULL AND o.receipt IS NOT NULL"
                ).fetchone()[0]
                == 1
            )
        assert db.execute("SELECT count(*) FROM simulations").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0


DATA = {"title": "Synthetic note", "body": "No private information"}
KEY = {"Idempotency-Key": "response-boundary"}


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["before_effect", "after_effect", "before_post", "after_post"])
async def test_storage_connection_loss_is_not_success_or_retry(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    from mcp_agent_server.idempotency.storage import OperationStore

    name = "local_effect" if boundary.endswith("effect") else "finish"
    original = getattr(OperationStore, name)
    calls = 0

    def fail(self: OperationStore, *args: Any) -> Any:
        nonlocal calls
        calls += 1
        if boundary.startswith("after"):
            original(self, *args)
        # Real local PostgreSQL connection loss; no fabricated success receipt.
        with self.audit.transaction() as db:
            db.execute("SELECT pg_terminate_backend(pg_backend_pid())")
        raise AssertionError("Connection termination must raise")

    monkeypatch.setattr(OperationStore, name, fail)
    async with client(cloud_app) as api:
        first = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert first.status_code == 503 and first.json()["outcome"] == "unknown"
        assert "result" not in first.json()
        count = 0 if boundary == "before_effect" else 1
        state = "COMPLETED" if boundary == "after_post" else "OUTCOME_UNKNOWN"
        durable(cloud_app, count, state, 1)
        monkeypatch.setattr(OperationStore, name, original)
        replay = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        if boundary == "after_post":
            assert replay.status_code == 200 and replay.json()["replayed"] is True
        else:
            assert replay.status_code == 503 and replay.json()["outcome"] == "unknown"
        assert calls == 1
        durable(cloud_app, count, state, 1)
    assert not cloud_app.broker.clients._entries


@pytest.mark.asyncio
async def test_lost_committed_sdk_reply_is_unknown_until_explicit_replay(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp import MCPError
    from mcp.client.session import ClientSession
    from mcp.types import REQUEST_TIMEOUT

    original = ClientSession.call_tool
    calls = 0

    async def lost(self: ClientSession, *args: Any, **kw: Any) -> Any:
        nonlocal calls
        calls += 1
        await original(self, *args, **kw)
        raise MCPError(code=REQUEST_TIMEOUT, message="SYNTHETIC-PRIVATE-ERROR")

    monkeypatch.setattr(ClientSession, "call_tool", lost)
    async with client(cloud_app) as api:
        response = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert response.status_code == 503 and response.json()["outcome"] == "unknown"
        assert "SYNTHETIC-PRIVATE-ERROR" not in response.text and calls == 1
        durable(cloud_app, 1, "COMPLETED", 1)
        monkeypatch.setattr(ClientSession, "call_tool", original)
        response = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert response.status_code == 200 and response.json()["replayed"] is True
        durable(cloud_app, 1, "COMPLETED", 1)
    assert not cloud_app.broker.clients._entries


@pytest.mark.asyncio
async def test_pending_identical_request_never_dispatches_twice(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio
    import threading

    from mcp_agent_server.idempotency.storage import OperationStore

    entered, release = threading.Event(), threading.Event()
    original = OperationStore.start
    calls = 0

    def held(self: OperationStore, *args: Any) -> None:
        nonlocal calls
        calls += 1
        original(self, *args)
        entered.set()
        assert release.wait(3)

    monkeypatch.setattr(OperationStore, "start", held)
    async with client(cloud_app) as api:
        first = asyncio.create_task(api.post("/api/v1/write_note", json=DATA, headers=KEY))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            second = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
            assert second.status_code == 409 and second.json()["error"] == "operation_in_progress"
        finally:
            release.set()
        first_result = await first
        assert first_result.status_code == 200 and first_result.json()["replayed"] is False
        replay = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert replay.status_code == 200 and replay.json()["replayed"] is True
        assert replay.json()["result"] == first_result.json()["result"] and calls == 1
        durable(cloud_app, 1, "COMPLETED", 1)


@pytest.mark.asyncio
async def test_distinct_concurrent_writes_have_distinct_durable_receipts(
    cloud_app: CloudApplication,
) -> None:
    import asyncio

    async with client(cloud_app) as api:
        responses = await asyncio.gather(
            *(
                api.post(
                    "/api/v1/write_note", json=DATA, headers={"Idempotency-Key": f"parallel-{i}"}
                )
                for i in range(3)
            )
        )
    assert all(r.status_code == 200 and r.json()["replayed"] is False for r in responses)
    identifiers = {r.json()["result"]["note_id"] for r in responses}
    assert len(identifiers) == 3
    with cloud_app.sessions.store.transaction() as db:
        assert {r[0] for r in db.execute("SELECT note_id FROM notes").fetchall()} == identifiers
        assert (
            db.execute("SELECT count(*) FROM operations WHERE state='COMPLETED'").fetchone()[0] == 3
        )
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events WHERE phase='post' AND status='succeeded'"
            ).fetchone()[0]
            == 3
        )
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
    assert not cloud_app.broker.clients._entries


@pytest.mark.asyncio
async def test_readiness_change_does_not_erase_completed_write(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_agent_server.idempotency.storage import OperationStore

    original = OperationStore.start

    def changed(self: OperationStore, *args: Any) -> None:
        original(self, *args)
        cloud_app.ready = False

    monkeypatch.setattr(OperationStore, "start", changed)
    async with client(cloud_app) as api:
        response = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert response.status_code == 200 and response.json()["outcome"] == "confirmed"
        refused = await api.post(
            "/api/v1/write_note", json=DATA, headers={"Idempotency-Key": "readiness-down"}
        )
        assert refused.status_code == 503 and refused.json() == {"error": "unavailable"}
    durable(cloud_app, 1, "COMPLETED", 1)


@pytest.mark.asyncio
async def test_single_dispatch_has_validated_schemas_before_effect(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx2

    send = httpx2.AsyncClient.send
    methods = []

    async def observe(self: httpx2.AsyncClient, request: httpx2.Request, **kw: Any) -> Any:
        methods.append(request.headers.get("mcp-method"))
        return await send(self, request, **kw)

    monkeypatch.setattr(httpx2.AsyncClient, "send", observe)
    async with client(cloud_app) as api:
        response = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert response.status_code == 200
    assert methods == ["server/discover", "tools/list", "tools/call"]
    durable(cloud_app, 1, "COMPLETED", 1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["changed_input", "changed_output", "missing", "cursor", "mismatch"]
)
async def test_no_unchecked_refresh_or_automatic_resend(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    from mcp import MCPError
    from mcp.client.session import ClientSession
    from mcp_types import HEADER_MISMATCH

    listing = Client.list_tools
    sends = 0

    async def changed(self: Client, *args: Any, **kw: Any) -> Any:
        result = await listing(self, *args, **kw)
        if fault.startswith("changed"):
            tool = next(t for t in result.tools if t.name == "write_note")
            if fault == "changed_input":
                tool.input_schema = {"type": "object"}
            else:
                tool.output_schema = {"type": "object"}
        if fault == "missing":
            result.tools = []
        if fault == "cursor":
            result.next_cursor = "untrusted"
        return result

    async def rejected(self: ClientSession, *args: Any, **kw: Any) -> Any:
        nonlocal sends
        sends += 1
        raise MCPError(code=HEADER_MISMATCH, message="Synthetic rejected request")

    monkeypatch.setattr(Client, "list_tools", changed)
    monkeypatch.setattr(ClientSession, "call_tool", rejected)
    async with client(cloud_app) as api:
        response = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert response.status_code == 503 and response.json()["outcome"] == "unknown"
    assert sends == (1 if fault == "mismatch" else 0)
    durable(cloud_app, 0, None, 0)
    assert not cloud_app.broker.clients._entries


def test_batched_setup_preserves_transaction_security(cloud_app: CloudApplication) -> None:
    with cloud_app.sessions.store.transaction(lock_timeout=0.75) as db:
        row = db.execute(
            "SELECT current_setting('search_path'),current_setting('statement_timeout'),"
            "current_setting('lock_timeout'),current_setting('idle_in_transaction_session_timeout'),"
            "current_setting('synchronous_commit'),current_setting('transaction_isolation')"
        ).fetchone()
        assert [row[i] for i in range(6)] == [
            "pg_catalog,mcp_agent",
            "2s",
            "750ms",
            "2500ms",
            "on",
            "read committed",
        ]
    durable(cloud_app, 0, None, 0)


@pytest.mark.asyncio
async def test_cancellation_after_confirmed_reply_is_not_swallowed(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    close = Client.__aexit__

    async def cancelled(self: Client, *args: Any) -> None:
        await close(self, *args)
        raise asyncio.CancelledError

    monkeypatch.setattr(Client, "__aexit__", cancelled)
    async with client(cloud_app) as api:
        with pytest.raises(asyncio.CancelledError):
            await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        durable(cloud_app, 1, "COMPLETED", 1)
        monkeypatch.setattr(Client, "__aexit__", close)
        response = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert response.status_code == 200 and response.json()["replayed"] is True
        durable(cloud_app, 1, "COMPLETED", 1)
    assert cloud_app.active == 0 and not cloud_app.broker.clients._entries


@pytest.mark.asyncio
async def test_public_response_delivery_failure_does_not_repeat_effect(
    cloud_app: CloudApplication,
) -> None:
    import httpx
    from starlette.types import Message, Receive, Scope, Send

    async def broken_wire(scope: Scope, receive: Receive, send: Send) -> None:
        async def lose(message: Message) -> None:
            if message["type"] == "http.response.body":
                raise OSError("Synthetic disconnected consumer")
            await send(message)

        await cloud_app(scope, receive, lose)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=broken_wire), base_url="https://demo.example.test"
    ) as api:
        with pytest.raises(OSError, match="Synthetic disconnected"):
            await api.post(
                "/api/v1/write_note",
                json=DATA,
                headers={**KEY, "Authorization": "Bearer " + "A" * 43},
            )
    durable(cloud_app, 1, "COMPLETED", 1)
    async with client(cloud_app) as api:
        response = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert response.status_code == 200 and response.json()["replayed"] is True
    durable(cloud_app, 1, "COMPLETED", 1)


@pytest.mark.asyncio
async def test_real_tcp_disconnect_after_commit_reconciles_once(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio
    import json
    import threading
    from urllib.parse import urlsplit

    from cloud.test_render_ingress import serve
    from mcp_agent_server.idempotency.storage import OperationStore

    entered, release = threading.Event(), threading.Event()
    finished = asyncio.Event()
    loop = asyncio.get_running_loop()
    original = OperationStore.finish

    def suspended(self: OperationStore, *args: Any) -> None:
        original(self, *args)
        entered.set()
        try:
            assert release.wait(3)
        finally:
            loop.call_soon_threadsafe(finished.set)

    monkeypatch.setattr(OperationStore, "finish", suspended)
    async with serve(cloud_app) as url:
        address = urlsplit(url)
        _, writer = await asyncio.open_connection(address.hostname, address.port)
        body = json.dumps(DATA).encode()
        headers = (
            "POST /api/v1/write_note HTTP/1.1\r\nHost: demo.example.test\r\n"
            "X-Forwarded-Proto: https\r\nAuthorization: Bearer "
            + "A" * 43
            + "\r\nContent-Type: application/json\r\nIdempotency-Key: response-boundary\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n"
        )
        writer.write(headers.encode() + body)
        await writer.drain()
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            writer.close()
            await writer.wait_closed()
        finally:
            release.set()
        async with asyncio.timeout(3):
            await finished.wait()
    durable(cloud_app, 1, "COMPLETED", 1)
    monkeypatch.setattr(OperationStore, "finish", original)
    async with client(cloud_app) as api:
        response = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert response.status_code == 200 and response.json()["replayed"] is True
    durable(cloud_app, 1, "COMPLETED", 1)
    assert not cloud_app.broker.clients._entries


def test_transaction_setup_is_one_round_trip_before_dispatch(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_agent_server.storage.postgres import PostgresConnection

    original = PostgresConnection.execute
    setup = []

    def execute(self: PostgresConnection, sql: str, parameters: Any = (), /) -> Any:
        if "set_config" in sql:
            setup.append(sql)
        return original(self, sql, parameters)

    monkeypatch.setattr(PostgresConnection, "execute", execute)
    with cloud_app.sessions.store.transaction() as db:
        assert len(setup) == 1 and setup[0].count("set_config") == 5
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0
    with cloud_app.sessions.store.pool.connection() as connection:
        assert connection.execute("SHOW statement_timeout").fetchone() == ("0",)
        assert connection.execute("SHOW lock_timeout").fetchone() == ("0",)


def test_setup_failure_cannot_reach_effect(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_agent_server.errors import ErrorCode, GuardrailError
    from mcp_agent_server.storage.postgres import PostgresConnection

    original = PostgresConnection.execute

    def fail(self: PostgresConnection, sql: str, parameters: Any = (), /) -> Any:
        if "set_config" in sql:
            original(self, sql, parameters)
            raise OSError("Synthetic setup failure")
        return original(self, sql, parameters)

    monkeypatch.setattr(PostgresConnection, "execute", fail)
    with pytest.raises(GuardrailError) as failure:
        with cloud_app.sessions.store.transaction():
            raise AssertionError("No effect may run after failed setup")
    assert failure.value.public.code == ErrorCode.AUDIT_UNAVAILABLE
    monkeypatch.setattr(PostgresConnection, "execute", original)
    durable(cloud_app, 0, None, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["error", "malformed"])
async def test_unconfirmed_result_never_becomes_success(
    cloud_app: CloudApplication, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    from mcp.client.session import ClientSession

    original = ClientSession.call_tool
    calls = 0

    async def invalid(self: ClientSession, *args: Any, **kw: Any) -> Any:
        nonlocal calls
        calls += 1
        response = await original(self, *args, **kw)
        return response.model_copy(
            update={"is_error": True}
            if kind == "error"
            else {"structured_content": {"persisted": True}}
        )

    monkeypatch.setattr(ClientSession, "call_tool", invalid)
    async with client(cloud_app) as api:
        response = await api.post("/api/v1/write_note", json=DATA, headers=KEY)
        assert response.status_code == 503 and response.json()["outcome"] == "unknown"
        assert "result" not in response.json() and calls == 1
    durable(cloud_app, 1, "COMPLETED", 1)
    assert not cloud_app.broker.clients._entries
