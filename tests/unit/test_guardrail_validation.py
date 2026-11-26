import pytest

from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.validation import HealthArguments, validate_arguments


class TypedArguments(HealthArguments):
    quantity: int


def test_empty_object_and_exact_size() -> None:
    assert validate_arguments({}, HealthArguments, 2, 1) == HealthArguments()
    assert validate_arguments({"quantity": 1}, TypedArguments, 14, 1) == TypedArguments(quantity=1)


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {"unexpected": "value"},
        {"token": "secret"},
        {"nested": {"data": "unexpected"}},
        {1: "bad"},
        {"a": {0}},
        {"a": float("nan")},
        {"a": "\ud800"},
    ],
)
def test_malformed_inputs(value: object) -> None:
    with pytest.raises(GuardrailError) as e:
        validate_arguments(value, HealthArguments, 128, 3)
    assert e.value.public.code == ErrorCode.INVALID_TOOL_ARGUMENTS


@pytest.mark.parametrize("value", ["1", True, 1.0])
def test_schema_rejects_coercion(value: object) -> None:
    with pytest.raises(GuardrailError):
        validate_arguments({"quantity": value}, TypedArguments, 128, 2)


def test_size_counts_utf8_and_escapes() -> None:
    for value, limit in [({"key": "é"}, 11), ({"key": "\n"}, 11), ({"key": "x" * 1000}, 32)]:
        with pytest.raises(GuardrailError) as e:
            validate_arguments(value, HealthArguments, limit, 4)
        assert e.value.public.code == ErrorCode.REQUEST_TOO_LARGE


def test_deep_or_cyclic_structures_are_bounded() -> None:
    cycle: list[object] = []
    cycle.append(cycle)
    nested: tuple[object, ...] = ({"key": [{}]}, {"key": cycle})
    for value in nested:
        with pytest.raises(GuardrailError) as e:
            validate_arguments(value, HealthArguments, 1024, 2)
        assert e.value.public.code == ErrorCode.INVALID_TOOL_ARGUMENTS
