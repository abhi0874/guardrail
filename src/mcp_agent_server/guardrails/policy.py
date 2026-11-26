"""Parse bounded local YAML into a versioned immutable policy snapshot."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as SchemaError
from pydantic import BaseModel, ConfigDict, Field, model_validator

from mcp_agent_server.config import PROJECT
from mcp_agent_server.errors import ErrorCode, GuardrailError

POLICIES = PROJECT / "policies"
DEFAULT_POLICY = POLICIES / "tool_access.yaml"
SCHEMA = POLICIES / "schema/policy.v1.schema.json"
Name = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
Scalar = str | int | bool


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)


class Equality(Frozen):
    op: Literal["equals"]
    field: Name
    value: Scalar


class Membership(Frozen):
    op: Literal["one_of"]
    field: Name
    values: tuple[Scalar, ...] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def homogeneous(self) -> "Membership":
        if len({type(v) for v in self.values}) != 1 or len(set(self.values)) != len(self.values):
            raise ValueError("Use distinct values of one type")
        return self


class IntegerRange(Frozen):
    op: Literal["integer_range"]
    field: Name
    minimum: int
    maximum: int

    @model_validator(mode="after")
    def ordered(self) -> "IntegerRange":
        if self.minimum > self.maximum:
            raise ValueError("Reversed interval")
        return self


class Rule(Frozen):
    tool: Name
    action: Literal["permit", "deny"]
    principals: tuple[Name, ...] = Field(min_length=1)
    roles: tuple[Name, ...]
    constraints: tuple[
        Annotated[Equality | Membership | IntegerRange, Field(discriminator="op")], ...
    ]
    approval_required: bool
    description: str | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def check_rule(self) -> "Rule":
        if self.action == "deny" and self.approval_required:
            raise ValueError("Deny cannot require approval")
        return self


class Document(Frozen):
    schema_version: Literal["1"]
    default_action: Literal["deny"]
    rules: tuple[Rule, ...] = Field(max_length=128)

    @model_validator(mode="after")
    def distinct(self) -> "Document":
        if len({r.tool for r in self.rules}) != len(self.rules):
            raise ValueError("One rule per tool")
        return self


@dataclass(frozen=True)
class Policy:
    document: Document
    digest: str


def contract() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **Document.model_json_schema(),
    }


class _Loader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.nodes.MappingNode, deep: bool = False) -> dict[Any, Any]:
        keys = [self.construct_object(k, deep=deep) for k, _ in node.value]
        if any(type(k) is not str for k in keys) or len(set(keys)) != len(keys):
            raise ValueError("Duplicate or non-string policy key")
        return super().construct_mapping(node, deep)


def parse_policy(raw: bytes) -> Policy:
    try:
        if len(raw) > 65536:
            raise ValueError("Policy exceeds limit")
        depth = 0
        for token in yaml.scan(raw, Loader=_Loader):
            if isinstance(
                token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken, yaml.tokens.TagToken)
            ):
                raise ValueError("Indirect or tagged YAML")
            if isinstance(
                token,
                (
                    yaml.tokens.BlockMappingStartToken,
                    yaml.tokens.BlockSequenceStartToken,
                    yaml.tokens.FlowSequenceStartToken,
                    yaml.tokens.FlowMappingStartToken,
                ),
            ):
                depth += 1
                if depth > 16:
                    raise ValueError("Excessive nesting")
            elif isinstance(
                token,
                (
                    yaml.tokens.BlockEndToken,
                    yaml.tokens.FlowSequenceEndToken,
                    yaml.tokens.FlowMappingEndToken,
                ),
            ):
                depth -= 1
        data = yaml.load(raw, Loader=_Loader)
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        if schema != contract():
            raise ValueError("Policy schema drift")
        Draft202012Validator(schema).validate(data)
        # Round-trip only JSON primitives, then use strict validation (including array -> tuple).
        document = Document.model_validate_json(json.dumps(data, allow_nan=False), strict=True)
        return Policy(document, hashlib.sha256(raw).hexdigest())
    except (
        OSError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
        yaml.YAMLError,
        SchemaError,
    ):
        raise GuardrailError(ErrorCode.INVALID_POLICY) from None


def load_policy(path: Path = DEFAULT_POLICY) -> Policy:
    path = PROJECT / path
    try:
        if (
            not path.is_relative_to(POLICIES)
            or ".." in path.parts
            or path.suffix != ".yaml"
            or any(p.is_symlink() for p in (path, *path.parents))
            or not path.is_file()
            or path.stat().st_nlink != 1
        ):
            raise ValueError("Invalid policy location")
        with path.open("rb") as file:
            return parse_policy(file.read(65537))
    except (OSError, ValueError):
        raise GuardrailError(ErrorCode.INVALID_POLICY) from None
