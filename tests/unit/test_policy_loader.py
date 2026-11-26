import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.policy import (
    DEFAULT_POLICY,
    POLICIES,
    SCHEMA,
    contract,
    load_policy,
    parse_policy,
)


def test_checked_schema_and_snapshot() -> None:
    stored = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(stored)
    assert stored == contract()
    policy = load_policy()
    assert policy.document.rules[0].tool == "health"
    with pytest.raises((FrozenInstanceError, AttributeError)):
        field = "digest"
        setattr(policy, field, "changed")
    with pytest.raises(ValidationError):
        policy.document.rules[0].action = "deny"
    with TemporaryDirectory(dir=POLICIES) as directory:
        copy = Path(directory) / "test.yaml"
        copy.write_bytes(DEFAULT_POLICY.read_bytes())
        live = load_policy(copy)
        copy.write_text("broken")
        assert live == policy
        with pytest.raises(GuardrailError):
            load_policy(copy)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"rules: [",
        b"x: !!python/object/apply:os.system [echo]",
        b"rules: []\nrules: []",
        b"outer: {dup: one, dup: two}",
        b"key: &anchor true\nother: *anchor",
        b"x: !!str 1",
        b"schema_version: '2'\ndefault_action: deny\nrules: []",
        b"schema_version: '1'\ndefault_action: permit\nrules: []",
        b"schema_version: '1'\ndefault_action: deny\nrules: []\nunknown: 1",
        b"x: " + b"[" * 18 + b"]" * 18,
        b"x" * 65537,
    ],
)
def test_invalid_yaml_is_safe(raw: bytes) -> None:
    with pytest.raises(GuardrailError) as e:
        parse_policy(raw)
    assert e.value.public.code == ErrorCode.INVALID_POLICY


@pytest.mark.parametrize(
    "change",
    [
        {"action": "other"},
        {"approval_required": "yes"},
        {"principals": []},
        {"extra": True},
        {"constraints": [{"op": "eval", "field": "x", "value": "2*2"}]},
        {"constraints": [{"op": "integer_range", "field": "x", "minimum": "1", "maximum": 2}]},
        {"constraints": [{"op": "integer_range", "field": "x", "minimum": 3, "maximum": 2}]},
        {"constraints": [{"op": "one_of", "field": "x", "values": [1, "1"]}]},
        {"constraints": [{"op": "one_of", "field": "x", "values": [1, 1]}]},
        {"constraints": [{"op": "equals", "field": "x", "value": {"nested": 1}}]},
        {"action": "deny", "approval_required": True},
    ],
)
def test_invalid_rule_rejected(change: dict[str, object]) -> None:
    doc = load_policy().document.model_dump(mode="json")
    doc["rules"][0].update(change)
    with pytest.raises(GuardrailError):
        parse_policy(json.dumps(doc).encode())


def test_duplicate_tool_and_unsafe_or_missing_paths(tmp_path: Path) -> None:
    doc = load_policy().document.model_dump(mode="json")
    doc["rules"] *= 2
    with pytest.raises(GuardrailError):
        parse_policy(json.dumps(doc).encode())
    for path in (
        tmp_path / "test.yaml",
        POLICIES / "absent.yaml",
        POLICIES / "../policies/tool_access.yaml",
    ):
        with pytest.raises(GuardrailError):
            load_policy(path)
