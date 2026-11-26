"""Trusted, server-side approvals for exact validated operations."""

import hashlib
import json
import re
import secrets
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID, uuid4

from pydantic import BaseModel, SecretStr

from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.storage.connection import Connection
from mcp_agent_server.storage.locks import locked

from .authorization import AuthorizationContext, authorize, canonical_arguments
from .policy import Policy


def fingerprint(value: object) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _token_digest(token: SecretStr) -> str:
    return hashlib.sha256(token.get_secret_value().encode()).hexdigest()


@dataclass(frozen=True)
class Binding:
    connection: str
    tool: str
    arguments: str
    identity: str
    policy: str

    @classmethod
    def create(
        cls, context: AuthorizationContext, tool: str, validated: BaseModel, policy: Policy
    ) -> "Binding":
        return cls(
            str(context.connection_id),
            tool,
            hashlib.sha256(canonical_arguments(validated).encode("utf-8")).hexdigest(),
            fingerprint([context.identity.principal, sorted(set(context.identity.roles))]),
            policy.digest,
        )

    def params(self) -> tuple[str, ...]:
        return self.connection, self.tool, self.arguments, self.identity, self.policy


class ApprovalGate:
    def __init__(
        self, store: AuditStore, policy: Policy, *, clock: Callable[[], float] = time.time
    ) -> None:
        self.store = store
        self.policy = policy
        self.clock = clock

    def issue(
        self,
        context: AuthorizationContext,
        tool: str,
        validated: BaseModel,
        *,
        issuer: str,
        ttl_seconds: int,
    ) -> SecretStr:
        decision = authorize(self.policy, context, tool, validated)
        if decision.error:
            raise GuardrailError(decision.error)
        if (
            not decision.approval_required
            or type(ttl_seconds) is not int
            or not 1 <= ttl_seconds <= 3600
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", issuer)
        ):
            raise GuardrailError(ErrorCode.APPROVAL_INVALID)
        binding = Binding.create(context, tool, validated, self.policy)
        token = SecretStr(secrets.token_urlsafe(32))
        with self.store.transaction() as db:
            now = self.clock()
            db.execute(
                "INSERT INTO approvals(reference,token_digest,connection_id,tool_name,"
                "arguments_digest,identity_digest,policy_digest,issued_at,expires_at,issuer)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid4()),
                    _token_digest(token),
                    *binding.params(),
                    now,
                    now + ttl_seconds,
                    issuer,
                ),
            )
        return token

    def revoke(self, token: SecretStr) -> None:
        with self.store.transaction() as db:
            changed = db.execute(
                "UPDATE approvals SET revoked_at=? WHERE token_digest=? "
                "AND consumed_at IS NULL AND revoked_at IS NULL",
                (self.clock(), _token_digest(token)),
            ).rowcount
            if changed != 1:
                raise GuardrailError(ErrorCode.APPROVAL_INVALID)

    def consume(self, event: AuditEvent, binding: Binding, token: SecretStr | None) -> AuditEvent:
        """Select under the write lock. Commit the pre-event and consumption together."""
        with self.store.transaction() as db:
            return self.consume_in_transaction(db, event, binding, token)

    def consume_in_transaction(
        self, db: Connection, event: AuditEvent, binding: Binding, token: SecretStr | None
    ) -> AuditEvent:
        db.row_factory = sqlite3.Row
        if token is None:
            row = db.execute(
                locked(
                    db,
                    "SELECT * FROM approvals WHERE connection_id=? AND tool_name=? "
                    "AND arguments_digest=? AND identity_digest=? AND policy_digest=? "
                    "ORDER BY rowid DESC LIMIT 1",
                ),
                binding.params(),
            ).fetchone()
        else:
            row = db.execute(
                locked(db, "SELECT * FROM approvals WHERE token_digest=?"), (_token_digest(token),)
            ).fetchone()
        if row is None:
            raise GuardrailError(
                ErrorCode.APPROVAL_REQUIRED if token is None else ErrorCode.APPROVAL_INVALID
            )
        actual = tuple(
            row[key]
            for key in (
                "connection_id",
                "tool_name",
                "arguments_digest",
                "identity_digest",
                "policy_digest",
            )
        )
        if actual != binding.params():
            raise GuardrailError(ErrorCode.APPROVAL_INVALID)
        now = self.clock()
        if row["revoked_at"] is not None:
            raise GuardrailError(ErrorCode.APPROVAL_REVOKED)
        if row["consumed_at"] is not None:
            raise GuardrailError(ErrorCode.APPROVAL_USED)
        if now < row["issued_at"] or now >= row["expires_at"]:
            raise GuardrailError(ErrorCode.APPROVAL_EXPIRED)
        pre = event.model_copy(update={"approval_ref": UUID(row["reference"])})
        self.store.insert_event(db, pre)
        changed = db.execute(
            "UPDATE approvals SET consumed_at=?,consumed_event=? WHERE "
            "reference=? AND consumed_at IS NULL AND revoked_at IS NULL",
            (now, str(pre.event_id), row["reference"]),
        ).rowcount
        if changed != 1:
            raise GuardrailError(ErrorCode.APPROVAL_INVALID)
        return pre
