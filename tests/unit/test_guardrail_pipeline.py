import asyncio
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import BaseModel

from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.config import Settings
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.models import GuardrailRequest, Status
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.guardrails.validation import HealthArguments
from mcp_agent_server.server import create_server


class Recorder:
    def __init__(self, fail_phase: str = "") -> None:
        self.events: list[AuditEvent] = []
        self.fail_phase = fail_phase

    def append(self, event: AuditEvent) -> None:
        if event.phase == self.fail_phase:
            raise RuntimeError("/private/test-secret SQL details")
        self.events.append(event)


def request(name: str = "health", args: object = None) -> GuardrailRequest:
    return GuardrailRequest(
        connection_id=uuid4(), tool_name=name, arguments={} if args is None else args
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,args,phase,code",
    [
        ("missing", {}, "", ErrorCode.UNKNOWN_TOOL),
        ("pending", {}, "", ErrorCode.TOOL_NOT_PERMITTED),
        ("health", {"token": "sensitive"}, "", ErrorCode.INVALID_TOOL_ARGUMENTS),
        ("health", {}, "pre", ErrorCode.AUDIT_UNAVAILABLE),
        ("health", {"token": "sensitive"}, "denied", ErrorCode.AUDIT_UNAVAILABLE),
    ],
)
async def test_denied_handler_never_runs(
    name: str, args: object, phase: str, code: ErrorCode
) -> None:
    store = Recorder(phase)
    pipeline = Pipeline(store, {"health": HealthArguments, "pending": HealthArguments}, 100, 2)
    calls = 0

    async def handler(_: BaseModel) -> str:
        nonlocal calls
        calls += 1
        return "unexpected"

    execution, result = await pipeline.execute(request(name, args), handler)
    assert calls == 0 and result is None and execution.status == Status.NOT_EXECUTED
    assert execution.error and execution.error.code == code and not execution.decision.allowed
    assert [e.phase for e in store.events] == ([] if phase else ["denied"])
    assert "sensitive" not in repr(store.events)


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_post", [False, True])
async def test_grant_after_pre_commit_and_post_failure(fail_post: bool) -> None:
    store = Recorder("post" if fail_post else "")
    pipeline = Pipeline(store, {"health": HealthArguments}, 100, 2)
    observed = []

    async def handler(_: BaseModel) -> str:
        assert [e.phase for e in store.events] == ["pre"]
        pipeline.claim("health")
        with pytest.raises(GuardrailError):
            pipeline.claim("health")
        observed.append(True)
        return "ok"

    execution, result = await pipeline.execute(request(), handler)
    assert observed == [True] and execution.status == Status.SUCCEEDED
    assert execution.decision.allowed
    if fail_post:
        assert execution.error and execution.error.code == ErrorCode.AUDIT_INTEGRITY
        assert result is None and len(store.events) == 1
    else:
        assert result == "ok" and execution.error is None
        assert store.events[1].parent_event_id == store.events[0].event_id
        assert store.events[1].request_id == execution.request_id
    with pytest.raises(GuardrailError):
        pipeline.claim("health")


@pytest.mark.asyncio
async def test_cancelled_dispatch_is_recorded() -> None:
    store = Recorder()
    pipeline = Pipeline(store, {"health": HealthArguments}, 100, 2)

    async def handler(_: BaseModel) -> str:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await pipeline.execute(request(), handler)
    assert store.events[-1].status == Status.INTERRUPTED


@pytest.mark.asyncio
async def test_programmatic_sdk_call_cannot_reach_business_handler(audit_db: Path) -> None:
    calls: list[bool] = []

    from mcp_agent_server.server import Health

    def health() -> Health:
        calls.append(True)
        raise AssertionError("business handler bypassed the pipeline")

    server = create_server(Settings(audit_db=audit_db), health_handler=health)
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError):
        await server.call_tool("health", {})
    assert not calls
    AuditStore(audit_db)
