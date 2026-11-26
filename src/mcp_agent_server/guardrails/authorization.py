"""Policy evaluation takes trusted context separately from validated tool data."""

import json
from dataclasses import dataclass
from uuid import UUID

from pydantic import BaseModel

from mcp_agent_server.errors import ErrorCode, GuardrailError

from .policy import Equality, Frozen, IntegerRange, Membership, Name, Policy


class Identity(Frozen):
    principal: Name
    roles: tuple[Name, ...] = ()


LOCAL = Identity(principal="local-anonymous")


class AuthorizationContext(Frozen):
    identity: Identity
    connection_id: UUID


@dataclass(frozen=True)
class Decision:
    error: ErrorCode | None = None
    approval_required: bool = False


def _matches(constraint: Equality | Membership | IntegerRange, value: object) -> bool:
    if isinstance(constraint, IntegerRange):
        return type(value) is int and constraint.minimum <= value <= constraint.maximum
    options = (constraint.value,) if isinstance(constraint, Equality) else constraint.values
    return any(type(value) is type(option) and value == option for option in options)


def canonical_arguments(validated: BaseModel) -> str:
    """Reject lossy serialization so two distinct validated inputs cannot share a grant."""

    def json_fields(value: object) -> object:
        if isinstance(value, BaseModel):
            return {name: json_fields(getattr(value, name)) for name in type(value).model_fields}
        if type(value) is dict and all(type(key) is str for key in value):
            return {key: json_fields(child) for key, child in value.items()}
        if type(value) is list:
            return [json_fields(child) for child in value]
        if value is None or type(value) in (bool, int, float, str):
            return value
        raise TypeError("Unsupported argument type")

    try:
        original = json.dumps(
            json_fields(validated),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        wire = json.dumps(
            validated.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        if original != wire:
            raise ValueError("Lossy argument representation")
        wire.encode("utf-8")
        return wire
    except (TypeError, ValueError, RecursionError):
        raise GuardrailError(ErrorCode.INVALID_TOOL_ARGUMENTS) from None


def authorize(
    policy: Policy, context: AuthorizationContext, tool: str, args: BaseModel
) -> Decision:
    rule = next((r for r in policy.document.rules if r.tool == tool), None)
    if rule is None:
        return Decision(ErrorCode.TOOL_NOT_PERMITTED)
    if rule.action == "deny":
        return Decision(ErrorCode.POLICY_DENIED)
    identity = context.identity
    if identity.principal not in rule.principals or not set(rule.roles).issubset(identity.roles):
        return Decision(ErrorCode.PRINCIPAL_DENIED)
    values = json.loads(canonical_arguments(args))
    if any(not _matches(c, values.get(c.field)) for c in rule.constraints):
        return Decision(ErrorCode.CONSTRAINT_DENIED)
    return Decision(approval_required=rule.approval_required)
