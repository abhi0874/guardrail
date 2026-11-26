"""The SDK peer can request a metadata refresh at the call boundary."""

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from integration import http_support
from mcp import MCPError, types
from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp_types import HEADER_MISMATCH, REQUEST_TIMEOUT

from mcp_agent_server.agent.fake import FakeLLM, scenario
from mcp_agent_server.agent.runner import run
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.errors import ErrorCode
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.policy import load_policy
from mcp_agent_server.server import create_server
from mcp_agent_server.tools.models import Message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("write", "change", "after_commit", "repeat"),
    [
        (False, "none", False, False),
        (False, "input", False, False),
        (False, "output", False, False),
        (False, "none", False, True),
        (True, "output", False, False),
        (True, "none", False, False),
        (True, "none", True, False),
        (True, "lost", True, False),
    ],
    ids=[
        "read",
        "changed-input",
        "changed-output",
        "second-refusal",
        "reported-note-reproduction",
        "unchanged-write-refresh",
        "already-committed-replay",
        "lost-write-receipt",
    ],
)
async def test_refresh_before_retry(
    audit_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    write: bool,
    change: str,
    after_commit: bool,
    repeat: bool,
) -> None:
    listings = calls = forwarded = 0
    operation_keys: list[object] = []
    name = "write_note" if write else "health"
    original_list = MCPServer.list_tools

    async def advertise(server: MCPServer[None]) -> list[types.Tool]:
        nonlocal listings
        listings += 1
        tools = [t.model_copy(deep=True) for t in await original_list(server)]
        if listings > 1:
            tool = next(t for t in tools if t.name == name)
            if change == "output":
                tool.output_schema = {"type": "object", "not": {}}
            elif change == "input":
                tool.input_schema["required"] = ["unregistered"]
        return tools

    async def intercept(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        nonlocal calls, forwarded
        if ctx.method != "tools/call":
            return await call_next(ctx)
        calls += 1
        if write:
            assert isinstance(ctx.params, dict)
            operation_keys.append(ctx.params["_meta"]["mcp-agent-server/idempotency-key"])
        if calls == 1 or repeat:
            if after_commit:
                await call_next(ctx)
                forwarded += 1
            if change == "lost":
                raise MCPError(
                    REQUEST_TIMEOUT, "Reply unavailable", {"code": "state_change_failed"}
                )
            raise MCPError(HEADER_MISMATCH, "Refresh listing")
        forwarded += 1
        return await call_next(ctx)

    def factory(*args: Any, **kwargs: Any) -> MCPServer[None]:
        server = create_server(*args, **kwargs)
        server.middleware.insert(0, intercept)
        return server

    monkeypatch.setattr(MCPServer, "list_tools", advertise)
    monkeypatch.setattr(http_support, "create_server", factory)

    model = (
        scenario("note")
        if write
        else FakeLLM(['{"calls":[{"name":"health","arguments":{}}]}', '{"content":"Done"}'])
    )
    async with http_support.listener(audit_db) as (url, clients, _):
        token, ref = clients.issue()
        ApprovalGate(AuditStore(audit_db), load_policy()).issue(
            ref.authorization,
            "send_message",
            Message(recipient="ops-lab", subject="Control", body="Unused grant"),
            issuer="operator",
            ttl_seconds=60,
        )
        async with http_support.client(url, token) as peer:
            outcome = await run(peer, model, "local test", allow_writes=frozenset({"write_note"}))
    assert listings == (1 if change == "lost" else 2)
    recording = outcome.recording
    if write:
        assert len(set(operation_keys)) == 1 and isinstance(operation_keys[0], str)
        (event,) = recording.events
        if change == "none":
            assert calls == 2 and forwarded == 1 + int(after_commit)
            assert recording.reason == "complete"
            assert event.persisted is True and event.replayed == after_commit
        else:
            assert calls == 1 and forwarded == int(after_commit)
            assert recording.reason == ("tool_error" if change == "lost" else "transport_error")
            assert (event.tool, event.outcome, event.code) == (
                name,
                "error",
                ErrorCode.OPERATION_OUTCOME_UNKNOWN,
            )
            assert event.persisted is None and outcome.answer is None
            assert outcome.timed_out is (change == "lost")
    elif change != "none":
        assert calls == 1 and forwarded == 0 and recording.reason == "transport_error"
    elif repeat:
        assert calls == 2 and forwarded == 0 and recording.reason == "tool_error"
    else:
        assert calls == 2 and forwarded == 1 and recording.reason == "complete"
        assert [(e.tool, e.outcome) for e in recording.events] == [("health", "ok")]

    with closing(sqlite3.connect(audit_db)) as db:
        committed = write and (change == "none" or after_commit)
        assert db.execute("SELECT count(*) FROM notes").fetchone() == (int(committed),)
        assert db.execute("SELECT state FROM operations").fetchall() == [("COMPLETED",)] * int(
            committed
        )
        decisions = [("new",)] * int(committed)
        if after_commit and change == "none":
            decisions.append(("replay",))
        assert (
            db.execute("SELECT decision FROM operation_attempts ORDER BY rowid").fetchall()
            == decisions
        )
        assert db.execute("SELECT count(*),count(consumed_event) FROM approvals").fetchone() == (
            1,
            0,
        )
        assert db.execute(
            "SELECT count(*) FROM audit_events WHERE phase='post' AND status='succeeded'"
        ).fetchone() == (int(committed) if write else forwarded,)
