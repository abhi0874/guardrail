import asyncio
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import BaseModel, SecretStr

from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.approval import ApprovalGate, fingerprint
from mcp_agent_server.guardrails.authorization import LOCAL, AuthorizationContext, Identity
from mcp_agent_server.guardrails.models import GuardrailRequest
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.guardrails.policy import Policy, parse_policy

from .operations import Args, snapshot


class Harness:
    def __init__(self, path: Path, policy: Policy | None = None) -> None:
        self.now = 1000.0
        self.policy = policy or snapshot()
        self.store = AuditStore(path)
        self.gate = ApprovalGate(self.store, self.policy, clock=lambda: self.now)
        self.context = AuthorizationContext(identity=LOCAL, connection_id=uuid4())
        self.args = Args(recipient="inbox", number=1, category="a")
        self.pipeline = Pipeline(
            self.store,
            {"write": Args, "copy": Args},
            2048,
            4,
            policy=self.policy,
            approvals=self.gate,
        )
        self.calls = 0

    def issue(self) -> SecretStr:
        return self.gate.issue(self.context, "write", self.args, issuer="operator", ttl_seconds=60)

    async def invoke(
        self,
        *,
        tool: str = "write",
        context: AuthorizationContext | None = None,
        values: dict[str, object] | None = None,
        token: SecretStr | None = None,
    ) -> ErrorCode | None:
        ctx = context or self.context
        req = GuardrailRequest(
            connection_id=ctx.connection_id,
            tool_name=tool,
            arguments=self.args.model_dump() if values is None else values,
        )

        async def handler(args: BaseModel) -> bool:
            self.pipeline.claim(tool)
            self.calls += 1
            return True

        execution, result = await self.pipeline.execute(
            req, handler, identity=ctx.identity, approval=token
        )
        if execution.error:
            assert result is None
            return execution.error.code
        assert result is True
        return None


@pytest.mark.asyncio
async def test_required_consumed_and_audit_binding(
    audit_db: Path, caplog: pytest.LogCaptureFixture
) -> None:
    h = Harness(audit_db)
    assert await h.invoke() == ErrorCode.APPROVAL_REQUIRED
    assert h.calls == 0
    token = h.issue()
    assert await h.invoke() is None
    assert await h.invoke(token=token) == ErrorCode.APPROVAL_USED
    assert h.calls == 1
    with closing(sqlite3.connect(audit_db)) as db:
        row = db.execute(
            "SELECT a.reference,a.consumed_event,e.phase,p.approval_ref,p.policy_digest "
            "FROM approvals a JOIN audit_events e ON e.event_id=a.consumed_event "
            "JOIN audit_policy p ON p.event_id=e.event_id"
        ).fetchone()
        assert row and row[0] == row[3] and row[2] == "pre" and row[4] == h.policy.digest
        phases = db.execute("SELECT phase,error_code FROM audit_events ORDER BY rowid").fetchall()
        assert phases == [
            ("denied", "approval_required"),
            ("pre", None),
            ("post", None),
            ("denied", "approval_consumed"),
        ]
        assert db.execute(
            "SELECT approval_ref FROM audit_policy JOIN audit_events USING(event_id) "
            "WHERE phase='post'"
        ).fetchone() == (row[0],)
    assert token.get_secret_value().encode() not in audit_db.read_bytes()
    assert token.get_secret_value() not in caplog.text
    assert "inbox" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mismatch", ["tool", "arguments", "connection", "identity", "policy", "token"]
)
async def test_exact_binding(audit_db: Path, mismatch: str) -> None:
    h = Harness(audit_db)
    token = h.issue()
    ctx = h.context
    values = h.args.model_dump()
    tool = "write"
    if mismatch == "tool":
        tool = "copy"
    elif mismatch == "arguments":
        values["number"] = 2
    elif mismatch == "connection":
        ctx = AuthorizationContext(identity=LOCAL, connection_id=uuid4())
    elif mismatch == "identity":
        ctx = AuthorizationContext(
            identity=Identity(principal=LOCAL.principal, roles=("reviewer",)),
            connection_id=ctx.connection_id,
        )
    elif mismatch == "policy":
        changed = parse_policy(
            json.dumps(h.policy.document.model_dump(mode="json"), indent=2).encode()
        )
        h = Harness(audit_db, changed)
    else:
        token = SecretStr("test-only-invalid-handle")
    assert (
        await h.invoke(tool=tool, context=ctx, values=values, token=token)
        == ErrorCode.APPROVAL_INVALID
    )
    assert h.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["expired", "revoked"])
async def test_time_and_revocation(audit_db: Path, state: str) -> None:
    h = Harness(audit_db)
    token = h.issue()
    if state == "expired":
        h.now += 60
        expected = ErrorCode.APPROVAL_EXPIRED
    else:
        h.gate.revoke(token)
        expected = ErrorCode.APPROVAL_REVOKED
    assert await h.invoke() == expected
    assert h.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("block", ["denied", "constraint", "principal", "invalid"])
async def test_grant_never_overrides_denial(audit_db: Path, block: str) -> None:
    h = Harness(audit_db)
    token = h.issue()
    ctx = h.context
    values = h.args.model_dump()
    if block == "denied":
        h = Harness(audit_db, snapshot(action="deny", approval=False))
        expected = ErrorCode.POLICY_DENIED
    elif block == "constraint":
        values["recipient"] = "forbidden"
        expected = ErrorCode.CONSTRAINT_DENIED
    elif block == "principal":
        ctx = AuthorizationContext(
            identity=Identity(principal="different"), connection_id=ctx.connection_id
        )
        expected = ErrorCode.PRINCIPAL_DENIED
    else:
        values["role"] = "admin"
        expected = ErrorCode.INVALID_TOOL_ARGUMENTS
    assert await h.invoke(context=ctx, values=values, token=token) == expected
    assert h.calls == 0
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("SELECT consumed_event FROM approvals").fetchone() == (None,)
        assert db.execute("SELECT error_code FROM audit_events").fetchone() == (expected.value,)


@pytest.mark.asyncio
async def test_concurrent_single_use(audit_db: Path) -> None:
    h = Harness(audit_db)
    other = Harness(audit_db)
    other.context = h.context
    h.issue()
    outcomes = await asyncio.gather(*(instance.invoke() for instance in [h, other] * 4))
    assert outcomes.count(None) == 1 and outcomes.count(ErrorCode.APPROVAL_USED) == 7
    assert h.calls + other.calls == 1
    with closing(sqlite3.connect(audit_db)) as db:
        assert dict(db.execute("SELECT phase,count(*) FROM audit_events GROUP BY phase")) == {
            "pre": 1,
            "post": 1,
            "denied": 7,
        }
    print("8 calls, 2 independent pipelines, 1 grant, 1 handler execution, 7 consumed denials")


@pytest.mark.asyncio
async def test_failed_commit_rolls_back_consumption_and_audit(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = Harness(audit_db)
    h.issue()

    def broken(db: sqlite3.Connection, event: AuditEvent) -> None:
        AuditStore.insert_event(db, event)
        # The FK fails at COMMIT, after the pre-event and consumption UPDATE.
        db.execute("PRAGMA defer_foreign_keys=ON")
        db.execute(
            "INSERT INTO audit_policy(event_id,policy_digest,principal) VALUES(?,?,?)",
            ("nonexistent-event", "test", "test"),
        )

    with monkeypatch.context() as patch:
        patch.setattr(h.store, "insert_event", broken)
        assert await h.invoke() == ErrorCode.AUDIT_UNAVAILABLE
    assert h.calls == 0
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("SELECT consumed_at,consumed_event FROM approvals").fetchone() == (
            None,
            None,
        )
        assert db.execute("SELECT count(*) FROM audit_events").fetchone() == (0,)
    assert await h.invoke() is None and h.calls == 1


def test_invalid_issuance_and_canonical_arguments(audit_db: Path) -> None:
    h = Harness(audit_db)
    for ttl in (0, -1, 3601, True):
        with pytest.raises(GuardrailError):
            h.gate.issue(h.context, "write", h.args, issuer="operator", ttl_seconds=ttl)
    with pytest.raises(GuardrailError):
        h.gate.issue(h.context, "missing", h.args, issuer="operator", ttl_seconds=60)
    with pytest.raises(GuardrailError):
        h.gate.revoke(SecretStr("invalid"))
    assert fingerprint({"a": "é", "b": 1}) == fingerprint({"b": 1, "a": "é"})
    assert fingerprint({"b": True}) != fingerprint({"b": 1})


@pytest.mark.asyncio
async def test_grant_survives_operator_process_exit(audit_db: Path) -> None:
    h = Harness(audit_db)
    # Real issuer process, stable test-established identity/connection, no secret on argv.
    import subprocess

    source = """
from operations import Args, snapshot
import sys
from uuid import UUID
from pathlib import Path
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails.authorization import LOCAL, AuthorizationContext
from mcp_agent_server.guardrails.approval import ApprovalGate
gate=ApprovalGate(AuditStore(Path(sys.argv[1])),snapshot(),clock=lambda:1000.)
gate.issue(AuthorizationContext(identity=LOCAL,connection_id=UUID(sys.argv[2])),"write",
           Args(recipient="inbox",number=1,category="a"),issuer="operator",ttl_seconds=60)
"""
    result = subprocess.run(
        [sys.executable, "-c", source, str(audit_db), str(h.context.connection_id)],
        cwd=Path(__file__).parent,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    fresh = Harness(audit_db)
    fresh.context = h.context
    assert await fresh.invoke() is None and fresh.calls == 1
    assert await h.invoke() == ErrorCode.APPROVAL_USED and h.calls == 0


@pytest.mark.asyncio
async def test_claimed_approval_in_arguments_grants_nothing(audit_db: Path) -> None:
    h = Harness(audit_db)
    values = h.args.model_dump()
    values["approved"] = True
    assert await h.invoke(values=values) == ErrorCode.APPROVAL_REQUIRED
    assert h.calls == 0


@pytest.mark.asyncio
async def test_post_failure_cannot_recycle_consumed_grant(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = Harness(audit_db)
    h.issue()
    with monkeypatch.context() as patch:

        def fail_post(event: AuditEvent) -> None:
            assert event.phase == "post"
            raise RuntimeError("test post failure")

        patch.setattr(h.store, "append", fail_post)
        assert await h.invoke() == ErrorCode.AUDIT_INTEGRITY
    assert h.calls == 1
    assert await h.invoke() == ErrorCode.APPROVAL_USED and h.calls == 1


@pytest.mark.asyncio
async def test_audit_failure_cannot_turn_policy_denial_into_dispatch(audit_db: Path) -> None:
    h = Harness(audit_db, snapshot(action="deny", approval=False))
    audit_db.rename(audit_db.with_suffix(".unavailable"))
    assert await h.invoke() == ErrorCode.AUDIT_UNAVAILABLE
    assert h.calls == 0


@pytest.mark.asyncio
async def test_wrong_policy_cannot_use_handle_for_ungated_operation(audit_db: Path) -> None:
    gated = Harness(audit_db)
    token = gated.issue()
    ungated = Harness(audit_db, snapshot(approval=False))
    assert await ungated.invoke(context=gated.context, token=token) == ErrorCode.APPROVAL_INVALID
    assert ungated.calls == 0
