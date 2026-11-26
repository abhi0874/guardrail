"""Claim decisions use SQLite writer serialization or PostgreSQL key and row locks."""

import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from pydantic import SecretStr

from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.approval import ApprovalGate, Binding
from mcp_agent_server.guardrails.models import Status
from mcp_agent_server.resilience.deadlines import Deadline
from mcp_agent_server.resilience.models import DeadlineExceeded
from mcp_agent_server.storage.connection import Connection
from mcp_agent_server.storage.locks import lock_key, locked

from .models import Decision, IdempotencyRecord, IdempotencyRequest, ReceiptCodec, State


@dataclass(frozen=True)
class Admission:
    decision: Decision
    operation_id: str
    pre: AuditEvent
    response: dict[str, object] | None = None
    error: ErrorCode | None = None


def _record(row: Any) -> IdempotencyRecord:
    return IdempotencyRecord(
        row["operation_id"],
        row["key_digest"],
        row["request_id"],
        Binding(*(row[k] for k in ("connection", "tool", "arguments", "identity", "policy"))),
        State(row["state"]),
        row["pre_id"],
        row["post_id"],
        row["created"],
        row["updated"],
        row["expires"],
        row["completed"],
        row["receipt"],
        row["error"],
    )


def _original_verified(db: Connection, record: IdempotencyRecord, pre: AuditEvent) -> bool:
    evidence = db.execute(
        """
        SELECT p.approval_ref FROM audit_events a JOIN audit_policy p USING(event_id)
        JOIN audit_events z ON z.parent_event_id=a.event_id AND z.request_id=a.request_id
        JOIN audit_policy q ON q.event_id=z.event_id
        JOIN operation_attempts t ON t.event_id=a.event_id AND t.operation_id=?
        WHERE t.decision='new' AND a.event_id=? AND a.request_id=? AND z.event_id=?
        AND a.phase='pre' AND a.allowed=1 AND a.validation='passed' AND a.status='not_executed'
        AND a.error_code IS NULL AND a.tool_name=? AND a.connection_id=?
        AND p.principal=? AND p.policy_digest=? AND p.approval_required=?
        AND z.phase='post' AND z.status='succeeded' AND z.allowed=1 AND z.error_code IS NULL
        AND z.tool_name=a.tool_name AND z.connection_id=a.connection_id
        AND q.policy_digest=p.policy_digest AND q.principal=p.principal
        AND q.approval_required=p.approval_required AND q.approval_ref IS p.approval_ref
        """,
        (
            record.operation_id,
            record.pre_id,
            record.request_id,
            record.post_id,
            pre.tool_name,
            str(pre.connection_id),
            pre.principal,
            pre.policy_digest,
            pre.approval_required,
        ),
    ).fetchone()
    if evidence is None:
        return False
    if not pre.approval_required:
        return evidence[0] is None
    return (
        db.execute(
            """
        SELECT 1 FROM approvals WHERE reference=? AND consumed_event=? AND consumed_at IS NOT NULL
        AND revoked_at IS NULL AND issued_at<=consumed_at AND consumed_at<expires_at
        AND connection_id=? AND tool_name=? AND arguments_digest=? AND identity_digest=?
        AND policy_digest=?
        """,
            (evidence[0], record.pre_id, *record.binding.params()),
        ).fetchone()
        is not None
    )


class OperationStore:
    def __init__(
        self, audit: AuditStore, gate: ApprovalGate, clock: Callable[[], float] = time.time
    ):
        self.audit = audit
        self.gate = gate
        self.clock = clock

    def admit(
        self,
        req: IdempotencyRequest,
        pre: AuditEvent,
        approval: SecretStr | None,
        mutation: ReceiptCodec,
        deadline: Deadline,
    ) -> Admission:
        try:
            return self._admit(req, pre, approval, mutation, deadline)
        except DeadlineExceeded:
            raise GuardrailError(ErrorCode.STATE_CHANGE_FAILED) from None

    def _admit(
        self,
        req: IdempotencyRequest,
        pre: AuditEvent,
        approval: SecretStr | None,
        mutation: ReceiptCodec,
        deadline: Deadline,
    ) -> Admission:
        with self.audit.transaction(lock_timeout=min(2.0, deadline.remaining())) as db:
            deadline.remaining()
            db.row_factory = sqlite3.Row
            lock_key(db, req.key_digest)
            row = db.execute(
                locked(db, "SELECT * FROM operations WHERE key_digest=?"), (req.key_digest,)
            ).fetchone()
            if row is None:
                if pre.approval_required:
                    pre = self.gate.consume_in_transaction(db, pre, req.binding, approval)
                else:
                    self.audit.insert_event(db, pre)
                now = self.clock()
                op = str(uuid4())
                db.execute(
                    """INSERT INTO operations
                    (operation_id,key_digest,request_id,connection,tool,arguments,identity,policy,
                    state,pre_id,created,updated,expires) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        op,
                        req.key_digest,
                        str(pre.request_id),
                        *req.binding.params(),
                        State.RESERVED,
                        str(pre.event_id),
                        now,
                        now,
                        now + mutation.total_seconds + 5,
                    ),
                )
                result = Admission(Decision.NEW, op, pre)
            else:
                result = self._duplicate(db, _record(row), req.binding, pre, mutation)
                attempt = (
                    pre
                    if result.error is None
                    else pre.model_copy(
                        update={"phase": "denied", "allowed": False, "error_code": result.error}
                    )
                )
                self.audit.insert_event(db, attempt)
            db.execute(
                "INSERT INTO operation_attempts VALUES (?,?,?)",
                (str(pre.event_id), result.operation_id, result.decision),
            )
            deadline.remaining()
            return result

    def _duplicate(
        self,
        db: Connection,
        record: IdempotencyRecord,
        binding: Binding,
        pre: AuditEvent,
        mutation: ReceiptCodec,
    ) -> Admission:
        state = record.state
        decision, error = Decision.DENIED, ErrorCode.STATE_CHANGE_FAILED
        if record.binding != binding:
            decision, error = Decision.CONFLICT, ErrorCode.IDEMPOTENCY_KEY_CONFLICT
        elif state is State.COMPLETED:
            if record.receipt is not None and _original_verified(db, record, pre):
                try:
                    return Admission(
                        Decision.REPLAY,
                        record.operation_id,
                        pre,
                        mutation.response(record.receipt, True),
                    )
                except GuardrailError as refusal:
                    return Admission(
                        Decision.DENIED, record.operation_id, pre, error=refusal.public.code
                    )
                except (ValueError, TypeError, RecursionError):
                    pass
            error = ErrorCode.IDEMPOTENCY_EVIDENCE_INVALID
        else:
            if state in (State.RESERVED, State.IN_PROGRESS) and self.clock() >= record.expires:
                state = self._recover(db, record, pre)
            if state in (State.RESERVED, State.IN_PROGRESS):
                decision, error = Decision.PENDING, ErrorCode.OPERATION_IN_PROGRESS
            elif state is State.OUTCOME_UNKNOWN:
                decision, error = Decision.UNKNOWN, ErrorCode.OPERATION_OUTCOME_UNKNOWN
        return Admission(decision, record.operation_id, pre, error=error)

    def _recover(self, db: Connection, record: IdempotencyRecord, attempt: AuditEvent) -> State:
        # Never give another owner the dispatch right. A reserved owner must still cross start().
        before = record.state is State.RESERVED
        state = State.FAILED_BEFORE_EFFECT if before else State.OUTCOME_UNKNOWN
        code = ErrorCode.STATE_CHANGE_FAILED if before else ErrorCode.OPERATION_OUTCOME_UNKNOWN
        row = db.execute(
            "SELECT p.approval_ref, a.argument_summary FROM audit_policy p "
            "JOIN audit_events a USING(event_id) WHERE event_id=?",
            (record.pre_id,),
        ).fetchone()
        if row is None:
            raise GuardrailError(ErrorCode.IDEMPOTENCY_EVIDENCE_INVALID)
        post = attempt.model_copy(
            update={
                "event_id": uuid4(),
                "request_id": UUID(record.request_id),
                "phase": "post",
                "parent_event_id": UUID(record.pre_id),
                "approval_ref": UUID(row[0]) if row[0] else None,
                "argument_summary": row[1],
                "error_code": code,
                "status": Status.NOT_EXECUTED if before else Status.INTERRUPTED,
                "duration_ms": max(0, self.clock() - record.created) * 1000,
            }
        )
        self.audit.insert_event(db, post)
        self._transition(db, record.operation_id, record.state, state, error=code, post=post)
        return state

    def _transition(
        self,
        db: Connection,
        op: str,
        old: State,
        new: State,
        *,
        error: ErrorCode | None = None,
        post: AuditEvent | None = None,
    ) -> None:
        now = self.clock()
        changed = db.execute(
            """UPDATE operations SET state=?,updated=?,error=?,post_id=?,
            completed=? WHERE operation_id=? AND state=?""",
            (
                new,
                now,
                error,
                str(post.event_id) if post else None,
                now if new is State.COMPLETED else None,
                op,
                old,
            ),
        ).rowcount
        if changed != 1:
            raise GuardrailError(ErrorCode.OPERATION_OUTCOME_UNKNOWN)

    def start(self, op: str) -> None:
        with self.audit.transaction() as db:
            self._transition(db, op, State.RESERVED, State.IN_PROGRESS)

    def observe(self, op: str, receipt: str, db: Connection) -> None:
        changed = db.execute(
            """UPDATE operations SET receipt=?,updated=? WHERE operation_id=?
            AND state=? AND (receipt IS NULL OR receipt=?)""",
            (receipt, self.clock(), op, State.IN_PROGRESS, receipt),
        ).rowcount
        if changed != 1:
            raise GuardrailError(ErrorCode.OPERATION_OUTCOME_UNKNOWN)

    def local_effect(
        self, op: str, mutation: ReceiptCodec, effect: Callable[[Connection], object]
    ) -> object:
        with self.audit.transaction() as db:
            if not db.execute(
                locked(
                    db,
                    "SELECT 1 FROM operations WHERE operation_id=? AND state=? AND receipt IS NULL",
                ),
                (op, State.IN_PROGRESS),
            ).fetchone():
                raise GuardrailError(ErrorCode.OPERATION_OUTCOME_UNKNOWN)
            value = effect(db)
            self.observe(op, mutation.encode(value), db)
            return value

    def save_receipt(self, op: str, receipt: str) -> None:
        with self.audit.transaction() as db:
            self.observe(op, receipt, db)

    def finish(self, op: str, post: AuditEvent) -> None:
        with self.audit.transaction() as db:
            self.audit.insert_event(db, post)
            self._transition(db, op, State.IN_PROGRESS, State.COMPLETED, post=post)

    def interrupt(self, op: str, post: AuditEvent) -> ErrorCode:
        code = post.error_code or ErrorCode.OPERATION_OUTCOME_UNKNOWN
        with self.audit.transaction() as db:
            row = db.execute(
                locked(db, "SELECT state FROM operations WHERE operation_id=?"), (op,)
            ).fetchone()
            if row and row[0] in (State.RESERVED, State.IN_PROGRESS):
                old = State(row[0])
                before = old is State.RESERVED
                state = State.FAILED_BEFORE_EFFECT if before else State.OUTCOME_UNKNOWN
                code = ErrorCode.STATE_CHANGE_FAILED if before else code
                post = post.model_copy(
                    update={
                        "error_code": code,
                        "status": Status.NOT_EXECUTED if before else Status.INTERRUPTED,
                    }
                )
                # Preserve uncertainty even when the original post-event sink is failing.
                self._transition(db, op, old, state, error=code)
        with self.audit.transaction() as db:
            row = db.execute(
                locked(db, "SELECT state,post_id FROM operations WHERE operation_id=?"), (op,)
            ).fetchone()
            if (
                row
                and row[0] in (State.FAILED_BEFORE_EFFECT, State.OUTCOME_UNKNOWN)
                and row[1] is None
            ):
                self.audit.insert_event(db, post)
                db.execute(
                    "UPDATE operations SET post_id=? WHERE operation_id=?", (str(post.event_id), op)
                )
        return code
