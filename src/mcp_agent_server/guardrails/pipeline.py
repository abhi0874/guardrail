"""A committed pre-event issues a single dispatch grant for this async invocation."""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from time import monotonic
from typing import Literal, Protocol, TypeVar, cast

from pydantic import BaseModel, SecretStr

from mcp_agent_server.audit.lifecycle import Persistence
from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.idempotency.models import Decision, IdempotencyRequest, Mutation
from mcp_agent_server.idempotency.service import MutationService
from mcp_agent_server.idempotency.storage import OperationStore
from mcp_agent_server.logging import LOGGER

from .approval import ApprovalGate, Binding
from .authorization import LOCAL, AuthorizationContext, Identity, authorize
from .models import GuardrailDecision, GuardrailExecution, GuardrailRequest, Status, Validation
from .output_filtering import OutputGuard, Render
from .policy import Policy, load_policy
from .rate_limiting import RateLimiter
from .secured_receipt import SecuredReceipt
from .security_settings import OutputSettings, RateSettings
from .validation import argument_summary, validate_arguments

T = TypeVar("T")


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> None: ...


@dataclass
class _Grant:
    name: str
    failure: ErrorCode | None = None
    active: bool = True
    used: bool = False


class Pipeline:
    def __init__(
        self,
        audit: AuditSink,
        schemas: Mapping[str, type[BaseModel]],
        max_bytes: int,
        max_depth: int,
        *,
        policy: Policy | None = None,
        approvals: ApprovalGate | None = None,
        outputs: OutputGuard | None = None,
        limiter: RateLimiter | None = None,
        constraint_errors: Mapping[str, ErrorCode] | None = None,
        mutations: Mapping[str, Mutation] | None = None,
    ) -> None:
        self.policy = policy if policy is not None else load_policy()
        if approvals is not None and (
            approvals.store is not audit or approvals.policy != self.policy
        ):
            raise ValueError("Approval gate must share the pipeline database and policy")
        self.approvals = approvals
        if self.approvals is None and isinstance(audit, AuditStore):
            self.approvals = ApprovalGate(audit, self.policy)
        self.outputs = outputs or OutputGuard(OutputSettings())
        self.limiter = limiter or RateLimiter(RateSettings())
        self.constraint_errors = dict(constraint_errors or {})
        self.mutations = dict(mutations or {})
        if self.mutations and (
            not isinstance(audit, AuditStore)
            or not self.approvals
            or not self.mutations.keys() <= schemas.keys()
        ):
            raise ValueError("Mutations require a registered schema and durable approval store")
        self.persistence = Persistence()
        self.mutation_service = (
            MutationService(
                OperationStore(audit, self.approvals),
                self.require_claimed_dispatch,
                self.persistence,
            )
            if self.mutations and isinstance(audit, AuditStore) and self.approvals
            else None
        )
        self.audit = audit
        self.schemas = dict(schemas)
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self._grant: ContextVar[_Grant | None] = ContextVar("tool_dispatch", default=None)

    def claim(self, name: str) -> None:
        grant = self._grant.get()
        if grant is None or not grant.active or grant.used or grant.name != name:
            raise GuardrailError(ErrorCode.TOOL_NOT_PERMITTED)
        grant.used = True

    @contextmanager
    def handler(self, name: str) -> Iterator[None]:
        self.claim(name)
        try:
            yield
        except GuardrailError as error:
            # The SDK may convert an exception to an isError result. Keep only its trusted code.
            grant = self._grant.get()
            assert grant is not None
            grant.failure = error.public.code
            raise

    def require_claimed_dispatch(self) -> None:
        """Only a handler that consumed this invocation's durable dispatch grant may proceed."""
        grant = self._grant.get()
        if grant is None or not grant.active or not grant.used:
            raise GuardrailError(ErrorCode.TOOL_NOT_PERMITTED)

    async def _dispatch(
        self, label: str, validated: BaseModel, dispatch: Callable[[BaseModel], Awaitable[T]]
    ) -> T:
        grant = _Grant(label)
        token = self._grant.set(grant)
        try:
            try:
                result = await dispatch(validated)
            except Exception:
                if grant.failure is not None:
                    raise GuardrailError(grant.failure) from None
                raise
            if grant.failure is not None:
                raise GuardrailError(grant.failure)
            if not grant.used:
                raise GuardrailError(ErrorCode.TOOL_EXECUTION_FAILED)
            return result
        finally:
            grant.active = False
            self._grant.reset(token)

    async def _persist(self, event: AuditEvent, failure: ErrorCode) -> None:
        try:
            await self.persistence.run(self.audit.append, event)
        except Exception:
            raise GuardrailError(failure) from None

    async def execute(
        self,
        request: GuardrailRequest,
        dispatch: Callable[[BaseModel], Awaitable[T]],
        *,
        identity: Identity = LOCAL,
        render: Render | None = None,
        idempotency_key: object = None,
        approval: SecretStr | None = None,
    ) -> tuple[GuardrailExecution, T | None]:
        started = monotonic()
        context = AuthorizationContext(connection_id=request.connection_id, identity=identity)
        requires_approval: bool | None = None
        name = request.tool_name
        known = isinstance(name, str) and name in self.schemas
        label = str(name) if known else "<unknown>"
        validation = Validation.UNCHECKED
        status = Status.NOT_EXECUTED
        error = None
        result = None
        handled = False

        def event(
            phase: Literal["pre", "post", "denied"],
            code: ErrorCode | None,
            parent: AuditEvent | None = None,
        ) -> AuditEvent:
            return AuditEvent(
                request_id=request.request_id,
                connection_id=request.connection_id,
                phase=phase,
                tool_name=label,
                validation=validation,
                status=status,
                allowed=phase != "denied",
                error_code=code,
                duration_ms=(monotonic() - started) * 1000,
                argument_summary=(
                    ("transport=streamable-http;" if request.transport == "streamable-http" else "")
                    + argument_summary(request.arguments)
                ),
                parent_event_id=parent.event_id if parent else None,
                policy_digest=self.policy.digest,
                principal=identity.principal,
                approval_required=requires_approval,
                approval_ref=parent.approval_ref if parent else None,
            )

        try:
            if not known:
                raise GuardrailError(ErrorCode.UNKNOWN_TOOL)
            validation = Validation.FAILED
            validated = validate_arguments(
                request.arguments, self.schemas[label], self.max_bytes, self.max_depth
            )
            mutation = self.mutations.get(label)
            key = (
                IdempotencyRequest.create(
                    idempotency_key, Binding.create(context, label, validated, self.policy)
                )
                if mutation
                else None
            )
            validation = Validation.PASSED
            policy_decision = authorize(self.policy, context, label, validated)
            if policy_decision.error is not None:
                code = policy_decision.error
                if code is ErrorCode.CONSTRAINT_DENIED:
                    code = self.constraint_errors.get(label, code)
                raise GuardrailError(code)
            requires_approval = policy_decision.approval_required
            await self.limiter.admit(request.connection_id)
            if approval is not None and not requires_approval:
                raise GuardrailError(ErrorCode.APPROVAL_INVALID)
            pre = event("pre", None)
            if mutation is not None:
                assert self.mutation_service is not None and key is not None
                outcome = await self.mutation_service.execute(
                    key,
                    pre,
                    approval,
                    SecuredReceipt(mutation, self.outputs, label, render),
                    lambda: self._dispatch(label, validated, dispatch),
                )
                handled = True
                if outcome.error:
                    error = GuardrailError(outcome.error).public
                    if (
                        outcome.decision is Decision.NEW
                        and outcome.error != ErrorCode.STATE_CHANGE_FAILED
                    ):
                        status = Status.INTERRUPTED
                else:
                    # Mutation registrations use the SDK wire result dictionary contract.
                    result = cast(T, outcome.response)
                    status = (
                        Status.SUCCEEDED if outcome.decision is Decision.NEW else Status.REPLAYED
                    )
            elif requires_approval:
                if self.approvals is None:
                    raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
                binding = Binding.create(context, label, validated, self.policy)
                pre = await asyncio.to_thread(self.approvals.consume, pre, binding, approval)
            else:
                await self._persist(pre, ErrorCode.AUDIT_UNAVAILABLE)
        except GuardrailError as denied:
            error = denied.public
            if error.code != ErrorCode.AUDIT_UNAVAILABLE or label in self.mutations:
                try:
                    await self._persist(event("denied", error.code), ErrorCode.AUDIT_UNAVAILABLE)
                except GuardrailError as unavailable:
                    error = unavailable.public
        if error is None and not handled:
            try:
                try:
                    result = await self._dispatch(label, validated, dispatch)
                    if render is not None:
                        if not isinstance(result, dict) or "structuredContent" not in result:
                            raise GuardrailError(ErrorCode.OUTPUT_UNSAFE)
                        result = cast(T, render(label, result["structuredContent"], None))
                    status = Status.SUCCEEDED
                except asyncio.CancelledError:
                    status = Status.INTERRUPTED
                    raise
                except GuardrailError as known_error:
                    status = Status.DISPATCH_FAILED
                    error = known_error.public
                except Exception:
                    status = Status.DISPATCH_FAILED
                    error = GuardrailError(ErrorCode.TOOL_EXECUTION_FAILED).public
                finally:
                    await self._persist(
                        event("post", error.code if error else None, pre), ErrorCode.AUDIT_INTEGRITY
                    )
            except GuardrailError as failure:
                error = failure.public

        if error:
            error = error.model_copy(update={"message": self.outputs.error_message(error.message)})
        denial = error if status == Status.NOT_EXECUTED else None
        decision = GuardrailDecision(
            allowed=denial is None,
            validation=validation,
            reason=denial.code if denial else None,
            explanation=denial.message if denial else "Validated dispatch permitted.",
        )
        execution = GuardrailExecution(
            request_id=request.request_id,
            decision=decision,
            status=status,
            duration_ms=(monotonic() - started) * 1000,
            error=error,
        )
        if error:
            logging.getLogger(LOGGER).warning(error.message, extra={"error_code": error.code})
        return execution, result if error is None else None
