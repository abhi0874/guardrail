import json
from uuid import uuid4

import pytest
from pydantic import BaseModel

from mcp_agent_server.errors import ErrorCode
from mcp_agent_server.guardrails.authorization import (
    LOCAL,
    AuthorizationContext,
    Identity,
    authorize,
)
from mcp_agent_server.guardrails.policy import parse_policy

from .operations import Args, snapshot


def test_matching_and_denial_reasons() -> None:
    ctx = AuthorizationContext(identity=LOCAL, connection_id=uuid4())
    args = Args(recipient="inbox", number=4, category="b", approved=True)
    assert authorize(snapshot(), ctx, "write", args).approval_required
    assert authorize(snapshot(), ctx, "absent", args).error == ErrorCode.TOOL_NOT_PERMITTED
    assert (
        authorize(snapshot(action="deny", approval=False), ctx, "write", args).error
        == ErrorCode.POLICY_DENIED
    )
    assert (
        authorize(snapshot(principal="operator"), ctx, "write", args).error
        == ErrorCode.PRINCIPAL_DENIED
    )
    assert (
        authorize(snapshot(roles=("admin",)), ctx, "write", args).error
        == ErrorCode.PRINCIPAL_DENIED
    )
    privileged = AuthorizationContext(
        identity=Identity(principal=LOCAL.principal, roles=("admin",)),
        connection_id=ctx.connection_id,
    )
    assert authorize(snapshot(roles=("admin",)), privileged, "write", args).error is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("recipient", "elsewhere"),
        ("number", 0),
        ("number", 5),
        ("number", True),
        ("number", "1"),
        ("category", "other"),
        ("recipient", 1),
    ],
)
def test_constraints_fail_closed(field: str, value: object) -> None:
    class TypedOther(BaseModel):
        recipient: object
        number: object
        category: object

    values = {"recipient": "inbox", "number": 1, "category": "a", field: value}
    args = TypedOther.model_validate(values)
    decision = authorize(
        snapshot(), AuthorizationContext(identity=LOCAL, connection_id=uuid4()), "write", args
    )
    assert decision.error == ErrorCode.CONSTRAINT_DENIED


@pytest.mark.parametrize("op", ["equals", "one_of"])
def test_exact_type_comparison(op: str) -> None:
    policy = snapshot().document.model_dump(mode="json")
    constraint = {
        "op": op,
        "field": "approved",
        ("value" if op == "equals" else "values"): 1 if op == "equals" else [1],
    }
    policy["rules"][0]["constraints"] = [constraint]
    decision = authorize(
        parse_policy(json.dumps(policy).encode()),
        AuthorizationContext(identity=LOCAL, connection_id=uuid4()),
        "write",
        Args(recipient="inbox", number=1, category="a", approved=True),
    )
    assert decision.error == ErrorCode.CONSTRAINT_DENIED


def test_canonicalization_rejects_hidden_argument_values() -> None:
    from pydantic import Field, SecretStr

    from mcp_agent_server.errors import GuardrailError
    from mcp_agent_server.guardrails.authorization import canonical_arguments

    class Hidden(BaseModel):
        recipient: str = Field(exclude=True)

    class Masked(BaseModel):
        credential: SecretStr

    for model in (Hidden(recipient="inbox"), Masked(credential=SecretStr("test-value"))):
        with pytest.raises(GuardrailError) as failure:
            canonical_arguments(model)
        assert failure.value.public.code == ErrorCode.INVALID_TOOL_ARGUMENTS
