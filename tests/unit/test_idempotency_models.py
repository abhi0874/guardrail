import pytest
from pydantic import BaseModel

from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.approval import Binding
from mcp_agent_server.guardrails.authorization import canonical_arguments
from mcp_agent_server.idempotency.models import IdempotencyRequest, Mutation

BOUND = Binding("conn", "tool", "args", "identity", "policy")


@pytest.mark.parametrize(
    "key", ["", "a" * 97, " ", " a", "a\n", "x\x00", "../f", "é", "\ud800", 1, True]
)
def test_invalid_key(key: object) -> None:
    with pytest.raises(GuardrailError) as err:
        IdempotencyRequest.create(key, BOUND)
    assert err.value.public.code == ErrorCode.INVALID_IDEMPOTENCY_KEY


def test_key_format_and_required() -> None:
    with pytest.raises(GuardrailError) as err:
        IdempotencyRequest.create(None, BOUND)
    assert err.value.public.code == ErrorCode.IDEMPOTENCY_KEY_REQUIRED
    assert IdempotencyRequest.create("aB_-123", BOUND) != IdempotencyRequest.create(
        "Ab_-123", BOUND
    )
    assert len(IdempotencyRequest.create("a" * 96, BOUND).key_digest) == 64


def test_canonical_json() -> None:
    class Payload(BaseModel):
        data: dict[str, object]

    a = Payload(data={"é": [True, None, 2, 2.5], "a": {}})
    b = Payload(data={"a": {}, "é": [True, None, 2, 2.5]})
    assert canonical_arguments(a) == canonical_arguments(b)
    for changed in [{"e\u0301": [True, None, 2, 2.5], "a": {}}, {"é": [1, None, 2, 2.5], "a": {}}]:
        assert canonical_arguments(a) != canonical_arguments(
            Payload.model_validate({"data": changed})
        )


def test_only_declared_bounded_receipt_fields() -> None:
    codec = Mutation(("count",))
    assert codec.encode({"count": 2, "unsafe": "private"}) == '{"count":2}'
    for value in [2**54, 1.25, "2", None]:
        with pytest.raises(ValueError):
            codec.encode({"count": value})
    with pytest.raises(ValueError):
        codec.response('{"count":1,"unsafe":true}', True)


@pytest.mark.parametrize("value", [("x",), {1: "value"}, "\ud800", float("inf"), float("nan")])
def test_ambiguous_validated_value_rejected(value: object) -> None:
    class Payload(BaseModel):
        value: object

    with pytest.raises(GuardrailError):
        canonical_arguments(Payload(value=value))
