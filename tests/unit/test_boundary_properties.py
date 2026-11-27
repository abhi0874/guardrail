"""Bounded, deterministic properties for local input and authorization boundaries."""

import json
from uuid import UUID

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_agent_server.agent.json_input import decode
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.authorization import AuthorizationContext, Identity, authorize
from mcp_agent_server.guardrails.validation import validate_arguments

from .operations import Args, snapshot

TEXT = st.text(max_size=48)
SMALL_INT = st.integers(min_value=-1000, max_value=1000)
JSON_VALUES = st.recursive(
    st.none() | st.booleans() | SMALL_INT | TEXT | st.floats(allow_nan=False, allow_infinity=False),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(TEXT, children, max_size=4),
    max_leaves=12,
)


@settings(max_examples=120, derandomize=True)
@given(JSON_VALUES)
def test_json_wire_round_trip(value: object) -> None:
    wire = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    encoded = wire.encode("utf-8")
    assert decode(encoded) == value
    with pytest.raises(json.JSONDecodeError):
        decode(encoded + b"!")


@settings(max_examples=64, derandomize=True)
@given(
    st.sampled_from(["NaN", "Infinity", "-Infinity", "1e999", "-1e999"]),
    st.integers(min_value=0, max_value=6),
)
def test_nonfinite_wire_values_fail_inside_nested_json(token: str, depth: int) -> None:
    wire = ("[" * depth + token + "]" * depth).encode("ascii")
    with pytest.raises(ValueError):
        decode(wire)


@settings(max_examples=120, derandomize=True)
@given(recipient=TEXT, category=TEXT, number=SMALL_INT, approved=st.booleans())
def test_argument_byte_budget_matches_compact_utf8(
    recipient: str, category: str, number: int, approved: bool
) -> None:
    data = {"recipient": recipient, "category": category, "number": number, "approved": approved}
    size = len(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    assert validate_arguments(data, Args, size, 1).model_dump() == data
    with pytest.raises(GuardrailError) as failure:
        validate_arguments(data, Args, size - 1, 1)
    assert failure.value.public.code == ErrorCode.REQUEST_TOO_LARGE


@settings(max_examples=100, derandomize=True)
@given(number=SMALL_INT, approved=st.booleans())
def test_strict_arguments_reject_coercion_and_extra_fields(number: int, approved: bool) -> None:
    original = {"recipient": "inbox", "category": "a", "number": number, "approved": approved}
    invalid = (
        dict(original, number=str(number)),
        dict(original, number=approved),
        dict(original, synthetic_extra=number),
    )
    for data in invalid:
        with pytest.raises(GuardrailError) as failure:
            validate_arguments(data, Args, 1024, 1)
        assert failure.value.public.code == ErrorCode.INVALID_TOOL_ARGUMENTS


@settings(max_examples=160, derandomize=True)
@given(
    principal=st.sampled_from(("operator", "visitor")),
    privileged=st.booleans(),
    recipient=st.sampled_from(("inbox", "archive")),
    category=st.sampled_from(("a", "b", "c")),
    number=st.integers(min_value=-1, max_value=6),
    approved=st.booleans(),
    tool=st.sampled_from(("write", "copy", "missing")),
)
def test_policy_uses_trusted_identity_and_keeps_approval_separate(
    principal: str,
    privileged: bool,
    recipient: str,
    category: str,
    number: int,
    approved: bool,
    tool: str,
) -> None:
    context = AuthorizationContext(
        identity=Identity(principal=principal, roles=("admin",) if privileged else ()),
        connection_id=UUID(int=0),
    )
    args = Args(recipient=recipient, number=number, category=category, approved=approved)
    decision = authorize(snapshot(principal="operator", roles=("admin",)), context, tool, args)

    if tool == "missing":
        expected = ErrorCode.TOOL_NOT_PERMITTED
    elif principal != "operator" or not privileged:
        expected = ErrorCode.PRINCIPAL_DENIED
    elif recipient != "inbox" or category not in ("a", "b") or not 1 <= number <= 4:
        expected = ErrorCode.CONSTRAINT_DENIED
    else:
        expected = None
    assert decision.error == expected
    assert decision.approval_required is (expected is None)
