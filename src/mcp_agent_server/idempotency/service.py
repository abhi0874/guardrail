"""Execute one owned mutation once, with the database as the authority across workers."""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from contextvars import ContextVar

from pydantic import SecretStr

from mcp_agent_server.audit.lifecycle import Persistence
from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.models import Status
from mcp_agent_server.logging import LOGGER
from mcp_agent_server.resilience.deadlines import Deadline
from mcp_agent_server.storage.connection import Connection

from .models import Decision, IdempotencyRequest, ReceiptCodec
from .storage import Admission, OperationStore


class MutationService:
    def __init__(
        self, store: OperationStore, require_claim: Callable[[], None], persistence: Persistence
    ) -> None:
        self.store = store
        self.persistence = persistence
        self.require_claim = require_claim
        self._owned: ContextVar[tuple[str, ReceiptCodec] | None] = ContextVar("owned", default=None)

    def operation_id(self) -> str:
        self.require_claim()
        owned = self._owned.get()
        if owned is None:
            raise GuardrailError(ErrorCode.TOOL_NOT_PERMITTED)
        return owned[0]

    async def local_effect(self, effect: Callable[[Connection], object]) -> object:
        self.require_claim()
        owned = self._owned.get()
        if owned is None:
            raise GuardrailError(ErrorCode.TOOL_NOT_PERMITTED)
        return await self.persistence.run(self.store.local_effect, *owned, effect)

    async def execute(
        self,
        request: IdempotencyRequest,
        pre: AuditEvent,
        approval: SecretStr | None,
        mutation: ReceiptCodec,
        dispatch: Callable[[], Awaitable[object]],
    ) -> Admission:
        started = time.monotonic()
        deadline = Deadline.start(mutation.total_seconds, time.monotonic)
        settled = await self.persistence.settle(
            self.store.admit, request, pre, approval, mutation, deadline
        )
        claim = settled.value
        if settled.cancelled:
            if claim.decision is Decision.NEW:
                await self._interrupt(claim, started)
            assert settled.cancellation is not None
            raise settled.cancellation
        if claim.decision is not Decision.NEW:
            return claim

        async def invoke() -> str:
            await self.persistence.run(self.store.start, claim.operation_id)
            deadline.remaining()
            token = self._owned.set((claim.operation_id, mutation))
            try:
                raw = await dispatch()
            finally:
                self._owned.reset(token)
            if not isinstance(raw, dict) or raw.get("isError"):
                raise ValueError("Expected a successful structured result")
            receipt = mutation.encode(raw.get("structuredContent"))
            # Separate from post auditing so an observed effect survives a post failure.
            await self.persistence.run(self.store.save_receipt, claim.operation_id, receipt)
            return receipt

        try:
            receipt = await deadline.attempt(mutation.total_seconds, invoke)
            response = mutation.response(receipt, False)
            post = self._post(claim, Status.SUCCEEDED, None, started)
            try:
                await self.persistence.run(self.store.finish, claim.operation_id, post)
            except Exception:
                raise GuardrailError(ErrorCode.AUDIT_INTEGRITY) from None
            return Admission(Decision.NEW, claim.operation_id, claim.pre, response)
        except asyncio.CancelledError:
            await self._interrupt(claim, started)
            raise
        except Exception as failure:
            integrity = (
                isinstance(failure, GuardrailError)
                and failure.public.code is ErrorCode.AUDIT_INTEGRITY
            )
            code = await self._interrupt(claim, started, integrity=integrity)
            return Admission(Decision.NEW, claim.operation_id, claim.pre, error=code)

    async def _interrupt(
        self, claim: Admission, started: float, *, integrity: bool = False
    ) -> ErrorCode:
        code = ErrorCode.AUDIT_INTEGRITY if integrity else ErrorCode.OPERATION_OUTCOME_UNKNOWN
        post = self._post(claim, Status.INTERRUPTED, code, started)
        try:
            return await self.persistence.run(self.store.interrupt, claim.operation_id, post)
        except Exception:
            logging.getLogger(LOGGER).error(
                "Mutation audit cleanup failed",
                extra={
                    "error_code": ErrorCode.AUDIT_INTEGRITY,
                    "request_id": str(claim.pre.request_id),
                },
            )
            return ErrorCode.AUDIT_INTEGRITY

    @staticmethod
    def _post(
        claim: Admission, status: Status, code: ErrorCode | None, started: float
    ) -> AuditEvent:
        pre = claim.pre
        return AuditEvent(
            request_id=pre.request_id,
            connection_id=pre.connection_id,
            phase="post",
            tool_name=pre.tool_name,
            validation=pre.validation,
            status=status,
            allowed=True,
            error_code=code,
            duration_ms=(time.monotonic() - started) * 1000,
            argument_summary=pre.argument_summary,
            parent_event_id=pre.event_id,
            policy_digest=pre.policy_digest,
            principal=pre.principal,
            approval_required=pre.approval_required,
            approval_ref=pre.approval_ref,
        )
