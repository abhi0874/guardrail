import json
from pathlib import Path
from uuid import uuid4

import pytest
from mcp import MCPError, types
from mcp_types import SERVER_INFO_META_KEY
from pydantic import BaseModel, TypeAdapter

from mcp_agent_server.errors import ErrorCode
from mcp_agent_server.guardrails.authorization import Identity
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.guardrails.policy import parse_policy
from mcp_agent_server.idempotency.models import Mutation
from mcp_agent_server.resilience.executor import ResilienceExecutor
from mcp_agent_server.resilience.models import Operation, Safety, Settings, TransientFailure

from .audit_support import connected, rows
from .mutation_fixture import Fixture, Increment, fixture_policy

pytestmark = pytest.mark.asyncio


async def test_replay_restart_conflict(audit_db: Path) -> None:
    conn = uuid4()
    first = Fixture(audit_db, conn)
    failure, _ = await first.call()
    assert failure.error and failure.error.code is ErrorCode.APPROVAL_REQUIRED
    first.approve()
    result, original = await first.call()
    assert not result.error and original and original["structuredContent"] == {"count": 1}
    for f in [first, Fixture(audit_db, conn)]:
        replay, cached = await f.call()
        assert (
            not replay.error
            and cached
            and cached["structuredContent"] == original["structuredContent"]
        )
        assert cached["_meta"] == {"mcp-agent-server/replayed": True}
        assert "private-debug" not in str(cached)
        assert f.count() == 1
    failure, _ = await f.call(amount=2)
    assert failure.error and failure.error.code is ErrorCode.IDEMPOTENCY_KEY_CONFLICT
    with first.store.transaction() as db:
        assert db.execute(
            "SELECT count(*) FROM approvals WHERE consumed_at IS NOT NULL"
        ).fetchone() == (1,)
        assert db.execute(
            "SELECT consumed_event=pre_id FROM approvals JOIN operations"
        ).fetchone() == (1,)
        assert db.execute("SELECT decision FROM operation_attempts ORDER BY rowid").fetchall() == [
            ("new",),
            ("replay",),
            ("replay",),
            ("conflict",),
        ]
    assert first.calls == 1 and f.calls == 0
    print("first=1 replay=1 reopened=1 conflict=idempotency_key_conflict grants_consumed=1")


async def test_scope_policy_and_untrusted_inputs(audit_db: Path) -> None:
    f = Fixture(audit_db, uuid4())
    f.approve()
    assert not (await f.call())[0].error
    for identity, expected in [
        (Identity(principal="operator"), ErrorCode.IDEMPOTENCY_KEY_CONFLICT),
        (
            Identity(principal="local-anonymous", roles=("manager",)),
            ErrorCode.IDEMPOTENCY_KEY_CONFLICT,
        ),
        (Identity(principal="outsider"), ErrorCode.PRINCIPAL_DENIED),
    ]:
        outcome, data = await f.pipe.execute(
            f.request(), f.handler, identity=identity, idempotency_key="sample-key"
        )
        assert outcome.error and outcome.error.code is expected and data is None
    for other, expected in [
        (Fixture(audit_db, uuid4()), ErrorCode.IDEMPOTENCY_KEY_CONFLICT),
        (
            Fixture(audit_db, f.conn, policy=fixture_policy(approval=False)),
            ErrorCode.IDEMPOTENCY_KEY_CONFLICT,
        ),
        (
            Fixture(audit_db, f.conn, policy=fixture_policy(action="deny", approval=False)),
            ErrorCode.POLICY_DENIED,
        ),
    ]:
        outcome, data = await other.call()
        assert outcome.error and outcome.error.code is expected and data is None
    for field in ["principal", "connection_id", "session", "approval", "roles"]:
        req = f.request().model_copy(update={"arguments": {field: "operator"}})
        outcome, _ = await f.pipe.execute(req, f.handler, idempotency_key="sample-key")
        assert outcome.error and outcome.error.code is ErrorCode.INVALID_TOOL_ARGUMENTS
    assert f.calls == f.count() == 1


@pytest.mark.parametrize("damage", ["approval", "audit"])
async def test_replay_denied_without_evidence(audit_db: Path, damage: str) -> None:
    f = Fixture(audit_db, uuid4())
    f.approve()
    assert not (await f.call())[0].error
    with f.store.transaction() as db:
        if damage == "approval":
            db.execute("UPDATE approvals SET consumed_event=NULL, consumed_at=NULL")
        else:
            db.execute(
                "DELETE FROM audit_policy WHERE event_id IN (SELECT post_id FROM operations)"
            )
    outcome, result = await f.call()
    assert outcome.error and outcome.error.code is ErrorCode.IDEMPOTENCY_EVIDENCE_INVALID
    assert result is None and f.count() == f.calls == 1


async def test_unsafe_dependency_one_attempt(audit_db: Path) -> None:
    f = Fixture(audit_db, uuid4())
    f.approve()
    executor = ResilienceExecutor(f.pipe, {"external": Settings(attempts=4)})
    attempts = 0

    async def external() -> None:
        nonlocal attempts
        attempts += 1
        raise TransientFailure()

    async def dispatch(data: BaseModel) -> dict[str, object]:
        result = await f.handler(data)
        await executor.run(Operation("external", external, Safety.UNSAFE_WRITE))
        return result

    for _ in range(2):
        response, result = await f.pipe.execute(f.request(), dispatch, idempotency_key="sample-key")
        assert (
            response.error
            and response.error.code is ErrorCode.OPERATION_OUTCOME_UNKNOWN
            and result is None
        )
    assert attempts == f.calls == f.count() == 1


async def test_sdk_mutation_receipt(audit_db: Path) -> None:
    from uuid import UUID

    filename = Path(__file__).with_name("mutation_fixture.py")
    bootstrap = (
        "import runpy; from pathlib import Path; "
        f"runpy.run_path({str(filename)!r})['serve'](Path({str(audit_db)!r}))"
    )
    meta = TypeAdapter(types.RequestParamsMeta).validate_python(
        {"mcp-agent-server/idempotency-key": "sample-key"}
    )
    async with connected(audit_db, bootstrap=bootstrap) as client:
        assert [tool.name for tool in (await client.list_tools()).tools] == ["increment"]
        with pytest.raises(MCPError) as missing:
            await client.call_tool("increment")
        assert missing.value.data["code"] == "idempotency_key_required"
        assert UUID(missing.value.data["request_id"])
        f = Fixture(audit_db, UUID(rows(audit_db)[0]["connection_id"]))
        f.approve()
        for replayed in [False, True]:
            result = await client.call_tool("increment", meta=meta)
            assert result.structured_content == {"count": 1}
            assert result.meta and result.meta["mcp-agent-server/replayed"] is replayed
            assert SERVER_INFO_META_KEY in result.meta
        assert f.count() == 1


async def test_ungated_mutation_replay(audit_db: Path) -> None:
    f = Fixture(audit_db, uuid4(), policy=fixture_policy(approval=False))
    for replay in (False, True):
        execution, result = await f.call()
        assert (
            not execution.error
            and result
            and result["_meta"] == {"mcp-agent-server/replayed": replay}
        )
    assert f.calls == f.count() == 1
    with f.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM approvals").fetchone() == (0,)


async def test_key_conflicts_across_permitted_tools(audit_db: Path) -> None:
    doc = fixture_policy(approval=False).document.model_dump(mode="json")
    doc["rules"].append({**doc["rules"][0], "tool": "second"})
    f = Fixture(audit_db, uuid4(), policy=parse_policy(json.dumps(doc).encode()))
    f.pipe = Pipeline(
        f.store,
        {"increment": Increment, "second": Increment},
        2048,
        5,
        policy=f.pipe.policy,
        mutations={name: Mutation(("count",)) for name in ("increment", "second")},
    )
    assert not (await f.call())[0].error
    other = f.request().model_copy(update={"tool_name": "second"})
    outcome, result = await f.pipe.execute(other, f.handler, idempotency_key="sample-key")
    assert outcome.error and outcome.error.code is ErrorCode.IDEMPOTENCY_KEY_CONFLICT
    assert result is None and f.calls == f.count() == 1
