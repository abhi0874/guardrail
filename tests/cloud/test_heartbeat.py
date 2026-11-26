"""Barrier-driven readiness checks with real PostgreSQL and MCP effects."""

import asyncio
import inspect
from collections.abc import AsyncIterator, Callable
from types import SimpleNamespace
from typing import Any, cast

import pytest
import pytest_asyncio

from cloud.conftest import cloud_app as original_app
from cloud.test_ingress import client
from mcp_agent_server.audit.lifecycle import Persistence
from mcp_agent_server.cloud import runtime
from mcp_agent_server.cloud.app import CloudApplication
from mcp_agent_server.cloud.settings import CloudSettings
from mcp_agent_server.config import Settings


@pytest.fixture
def probe(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {
        "tick": asyncio.Event(),
        "entered": asyncio.Event(),
        "release": asyncio.Event(),
        "settled": asyncio.Event(),
        "fail": False,
    }
    sleep, run = asyncio.sleep, Persistence.run

    async def clock(seconds: float) -> None:
        if seconds == 5:
            await state["tick"].wait()
            state["tick"].clear()
        else:
            await sleep(seconds)

    async def persist(self: Persistence, fn: Callable[..., Any], *args: Any, **kw: Any) -> Any:
        if fn.__name__ != "check":
            return await run(self, fn, *args, **kw)
        state["entered"].set()
        await state["release"].wait()
        try:
            if state["fail"]:
                raise OSError("synthetic probe failure")
            return await run(self, fn, *args, **kw)
        finally:
            state["settled"].set()

    monkeypatch.setattr(runtime, "asyncio", SimpleNamespace(**{**vars(asyncio), "sleep": clock}))
    monkeypatch.setattr(Persistence, "run", persist)
    return state


@pytest_asyncio.fixture
async def instrumented(
    probe: dict[str, Any],
    postgres: dict[str, str],
    pg_settings: Settings,
    cloud_config: CloudSettings,
) -> AsyncIterator[CloudApplication]:
    factory = cast(Callable[..., AsyncIterator[CloudApplication]], inspect.unwrap(original_app))
    async for app in factory(postgres, pg_settings, cloud_config):
        yield app
    assert app.sessions.persistence.pending == 0


@pytest.mark.asyncio
async def test_pending_probe_preserves_ready_and_effects(
    instrumented: CloudApplication,
    probe: dict[str, Any],
) -> None:
    app = instrumented
    async with asyncio.timeout(5):
        probe["tick"].set()
        await probe["entered"].wait()
        async with client(app) as api:
            body = {"title": "Probe overlap", "body": "Synthetic local content"}
            headers = {"Idempotency-Key": "probe-overlap"}
            response = await api.post("/api/v1/write_note", json=body, headers=headers)
            with app.sessions.store.transaction() as db:
                before = db.execute("SELECT count(*) FROM notes").fetchone()[0]
            assert response.status_code == 200, {"response": response.json(), "notes": before}
            assert before == 1 and response.json()["replayed"] is False
            replay = await api.post("/api/v1/write_note", json=body, headers=headers)
            assert replay.status_code == 200 and replay.json()["replayed"] is True
        probe["release"].set()
        await probe["settled"].wait()
        assert app.ready
    with app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert (
            db.execute("SELECT count(*) FROM operations WHERE state='COMPLETED'").fetchone()[0] == 1
        )
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone()[0] == 1
        # Replay has its own admission/pre-event; the single execution owns the post-event.
        assert db.execute("SELECT count(*) FROM audit_events WHERE phase='pre'").fetchone()[0] == 2
        assert (
            db.execute(
                "SELECT count(*) FROM audit_events p JOIN audit_events e "
                "ON e.parent_event_id=p.event_id AND e.request_id=p.request_id "
                "WHERE e.phase='post'"
            ).fetchone()[0]
            == 1
        )
        assert (
            db.execute(
                "SELECT count(*) FROM operation_attempts WHERE decision='replay'"
            ).fetchone()[0]
            == 1
        )
    assert not app.broker.clients._entries


@pytest.mark.asyncio
async def test_failed_probe_blocks_writes_until_successful_probe(
    instrumented: CloudApplication,
    probe: dict[str, Any],
) -> None:
    app = instrumented
    async with asyncio.timeout(5):
        probe["fail"] = True
        probe["tick"].set()
        await probe["entered"].wait()
        probe["release"].set()
        await probe["settled"].wait()
        assert not app.ready
        async with client(app) as api:
            response = await api.post(
                "/api/v1/write_note",
                json={"title": "blocked", "body": "synthetic"},
                headers={"Idempotency-Key": "blocked-probe"},
            )
            assert response.status_code == 503 and response.json() == {"error": "unavailable"}
        with app.sessions.store.transaction() as db:
            assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0
            assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == 0
        for name in ("entered", "release", "settled"):
            probe[name].clear()
        probe["fail"] = False
        probe["tick"].set()
        await probe["entered"].wait()
        assert not app.ready
        probe["release"].set()
        await probe["settled"].wait()
        assert app.ready
