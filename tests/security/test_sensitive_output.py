"""Synthetic cache-boundary attacks; no production secret or external delivery."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from integration.audit_support import connected
from integration.mutation_fixture import Fixture, fixture_policy, increment
from integration.test_output_guardrails import CANARY, LOGGING
from integration.test_production_tools import BOOT, denial, key, operator
from pydantic import BaseModel, ConfigDict

from mcp_agent_server.errors import ErrorCode
from mcp_agent_server.guardrails.output_filtering import OutputGuard
from mcp_agent_server.guardrails.security_settings import OutputSettings
from mcp_agent_server.idempotency.models import Mutation
from mcp_agent_server.storage.connection import Connection
from mcp_agent_server.tools.models import Message


class TextReceipt(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    text: str


class TextMutation(Mutation):
    def encode(self, data: object) -> str:
        value = TextReceipt.model_validate(data, strict=True)
        return json.dumps(value.model_dump(), sort_keys=True, separators=(",", ":"))


@pytest.mark.asyncio
async def test_safe_receipt_ingress_and_current_replay_filter(
    audit_db: Path, caplog: pytest.LogCaptureFixture
) -> None:
    f = Fixture(audit_db, uuid4(), policy=fixture_policy(approval=False))
    f.pipe.mutations["increment"] = TextMutation(("text",))
    f.pipe.outputs = OutputGuard(OutputSettings.model_validate({"literals": [CANARY]}))
    text = CANARY + " Public information"

    async def dispatch(data: BaseModel) -> dict[str, object]:
        f.pipe.claim("increment")
        f.calls += 1
        assert f.pipe.mutation_service

        def effect(db: Connection) -> dict[str, str]:
            increment(db, 1)
            return {"text": text}

        receipt = await f.pipe.mutation_service.local_effect(effect)
        return {"structuredContent": receipt}

    def render(tool: str, data: object, replay: bool | None) -> dict[str, object]:
        return f.pipe.outputs.render(tool, data, replay, None, False)

    execution, result = await f.pipe.execute(
        f.request(), dispatch, idempotency_key="safe", render=render
    )
    assert not execution.error and result
    assert result["structuredContent"] == {"text": "[REDACTED] Public information"}
    with f.store.transaction() as db:
        receipt = db.execute("SELECT receipt FROM operations").fetchone()[0]
        assert CANARY not in receipt and "[REDACTED]" in receipt
    assert CANARY.encode() not in audit_db.read_bytes() and CANARY not in caplog.text

    # New operator rule is applied to a historical receipt, without rewriting the
    # immutable completed row or dispatching its business effect a second time.
    f.pipe.outputs = OutputGuard(
        OutputSettings.model_validate({"literals": [CANARY, "Public information"]})
    )
    execution, replay = await f.pipe.execute(
        f.request(), dispatch, idempotency_key="safe", render=render
    )
    assert not execution.error and replay
    assert replay["structuredContent"] == {"text": "[REDACTED] [REDACTED]"}
    assert f.count() == 1 and f.calls == 1
    with f.store.transaction() as db:
        assert db.execute("SELECT receipt FROM operations").fetchone()[0] == receipt
    print("cache_ingress=redacted current_replay=redacted actual_effects=1 raw_canary_absent=True")


@pytest.mark.asyncio
async def test_local_filter_failure_rolls_back_effect_and_never_retries(audit_db: Path) -> None:
    f = Fixture(audit_db, uuid4(), policy=fixture_policy(approval=False))
    f.pipe.outputs = OutputGuard(OutputSettings.model_validate({"literals": ["1234"]}))
    with f.store.transaction() as db:
        db.execute("PRAGMA application_id=1233")
    first, result = await f.call()
    assert (
        first.error and first.error.code is ErrorCode.OPERATION_OUTCOME_UNKNOWN and result is None
    )
    second, _ = await f.call()
    assert second.error and second.error.code is ErrorCode.OPERATION_OUTCOME_UNKNOWN
    assert f.count() == 1233 and f.calls == 1
    with f.store.transaction() as db:
        assert db.execute("SELECT state,receipt FROM operations").fetchall() == [
            ("OUTCOME_UNKNOWN", None)
        ]
    print("local_filter_failure: effect_rolled_back=True retries=0 state=OUTCOME_UNKNOWN")


@pytest.mark.asyncio
async def test_committed_simulation_failure_is_truthful(audit_db: Path) -> None:
    config = {"MCP_AGENT_OUTPUT_LITERALS": json.dumps(["ops-lab"])}
    msg = Message(recipient="ops-lab", subject="Local", body="Synthetic")
    async with connected(audit_db, bootstrap=LOGGING + BOOT, limits=config) as client:
        await client.call_tool("health")
        operator(audit_db, msg)
        await denial(client, "send_message", msg.model_dump(), "operation_outcome_unknown", "send")
        await denial(client, "send_message", msg.model_dump(), "operation_outcome_unknown", "send")
        assert (audit_db.parent / "outbox-count").read_text() == "1"
    from mcp_agent_server.audit.storage import AuditStore

    with AuditStore(audit_db).transaction() as db:
        assert db.execute("SELECT state,receipt FROM operations").fetchall() == [
            ("OUTCOME_UNKNOWN", None)
        ]
        assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (1,)
        assert db.execute(
            "SELECT count(*) FROM audit_events WHERE status='succeeded' "
            "AND tool_name='send_message'"
        ).fetchone() == (0,)
    assert b"ops-lab" not in audit_db.read_bytes()
    assert "ops-lab" not in (audit_db.parent / "stderr.jsonl").read_text()
    print(
        "committed_simulation_filter_failure: outbox=1 consumed=1 "
        "receipt=NULL success=False retries=0"
    )


@pytest.mark.asyncio
async def test_completed_production_receipt_cannot_bypass_changed_filter(audit_db: Path) -> None:
    from mcp_agent_server.audit.storage import AuditStore

    conn = uuid4()
    prefix = f"""
from uuid import UUID
from mcp_agent_server.guardrails.middleware import ToolMiddleware
original=ToolMiddleware.__init__
def init(self,*args,**kwargs):
    original(self,*args,**kwargs)
    self.connection_id=UUID("{conn}")
ToolMiddleware.__init__=init
"""
    msg = Message(recipient="ops-lab", subject="Local", body="Synthetic")
    async with connected(audit_db, bootstrap=prefix + BOOT) as client:
        await client.call_tool("health")
        operator(audit_db, msg)
        result = await client.call_tool("send_message", msg.model_dump(), meta=key("sent"))
        assert result.structured_content
        token = str(result.structured_content["simulation_id"])
    config = {"MCP_AGENT_OUTPUT_LITERALS": json.dumps([token])}
    async with connected(audit_db, bootstrap=prefix + BOOT, limits=config) as restarted:
        await denial(restarted, "send_message", msg.model_dump(), "output_unsafe", "sent")
        assert (audit_db.parent / "outbox-count").read_text() == "0"
    with AuditStore(audit_db).transaction() as db:
        assert db.execute("SELECT state FROM operations").fetchall() == [("COMPLETED",)]
        assert db.execute("SELECT decision FROM operation_attempts ORDER BY rowid").fetchall() == [
            ("new",),
            ("denied",),
        ]
    print("changed_filter: historical_identifier_replay=output_unsafe dispatches_after_restart=0")
