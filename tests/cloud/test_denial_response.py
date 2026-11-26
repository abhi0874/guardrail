"""Verify the public outcome against the real loopback MCP and PostgreSQL records."""

from typing import Any

import pytest
from mcp import MCPError
from mcp.client.session import ClientSession

from cloud.test_ingress import client
from mcp_agent_server.cloud.app import CloudApplication


@pytest.mark.asyncio
async def test_binding_conflict_denies_only_this_attempt(cloud_app: CloudApplication) -> None:
    key = {"Idempotency-Key": "local-denial"}
    body = {"title": "Synthetic note", "body": "First client's content"}
    async with client(cloud_app) as api:
        first = await api.post("/api/v1/write_note", json=body, headers=key)
        assert first.status_code == 200 and first.json()["outcome"] == "confirmed"
        conflict = await api.post(
            "/api/v1/write_note",
            json=body,
            headers={**key, "Authorization": "Bearer " + "B" * 43},
        )

    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == 1
        assert db.execute("SELECT state FROM operations").fetchone()[0] == "COMPLETED"
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM simulations").fetchone()[0] == 0
        attempt = db.execute(
            "SELECT a.connection_id,a.phase,a.allowed,a.status,a.error_code "
            "FROM operation_attempts t JOIN audit_events a ON a.event_id=t.event_id "
            "WHERE t.decision='conflict'"
        ).fetchall()
        assert len(attempt) == 1
        assert tuple(attempt[0].values) == (
            str(cloud_app.config.clients[1].identifier),
            "denied",
            0,
            "not_executed",
            "idempotency_key_conflict",
        )

    assert conflict.status_code == 409
    assert conflict.json() == {
        "error": "idempotency_key_conflict",
        "outcome": "denied",
        "request_id": conflict.headers["x-request-id"],
    }


def test_conflict_requires_dispatch_provenance() -> None:
    from mcp_agent_server.cloud.app import failure_code
    from mcp_agent_server.cloud.broker import DeniedKeyConflict
    from mcp_agent_server.errors import ErrorCode

    raw = MCPError(code=-32000, message="unverified", data={"code": "idempotency_key_conflict"})
    assert failure_code(raw) is None
    assert failure_code(ExceptionGroup("transport", [DeniedKeyConflict()])) == (
        ErrorCode.IDEMPOTENCY_KEY_CONFLICT
    )
    assert failure_code(ExceptionGroup("mixed", [DeniedKeyConflict(), TimeoutError()])) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_number,data",
    [
        (-32000, {"code": "idempotency_key_conflict", "request_id": "invalid", "retryable": False}),
        (
            -32001,
            {
                "code": "idempotency_key_conflict",
                "request_id": "00000000-0000-0000-0000-000000000001",
                "retryable": False,
            },
        ),
        (
            -32000,
            {
                "code": "idempotency_key_conflict",
                "request_id": "00000000-0000-0000-0000-000000000001",
            },
        ),
        (-32000, {"code": "operation_in_progress"}),
        (-32000, {"code": "operation_outcome_unknown"}),
    ],
)
async def test_incomplete_conflict_after_commit_stays_unknown(
    cloud_app: CloudApplication,
    monkeypatch: pytest.MonkeyPatch,
    error_number: int,
    data: dict[str, Any],
) -> None:
    original = ClientSession.call_tool
    calls = 0

    async def damaged_reply(self: ClientSession, *args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        await original(self, *args, **kwargs)
        raise MCPError(code=error_number, message="incomplete reply", data=data)

    monkeypatch.setattr(ClientSession, "call_tool", damaged_reply)
    async with client(cloud_app) as api:
        response = await api.post(
            "/api/v1/write_note",
            json={"title": "Local test", "body": "Response lost after commit"},
            headers={"Idempotency-Key": "damaged-reply"},
        )
    assert calls == 1
    expected_status = 409 if data.get("code") == "operation_in_progress" else 503
    assert response.status_code == expected_status and response.json()["outcome"] == "unknown"
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT state FROM operations").fetchone()[0] == "COMPLETED"
        assert db.execute("SELECT count(*) FROM operation_attempts").fetchone()[0] == 1
