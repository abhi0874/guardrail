"""Bound compact JSON before strict per-tool schema validation."""

import json
import math

from pydantic import BaseModel, ConfigDict, ValidationError

from mcp_agent_server.errors import ErrorCode, GuardrailError


class HealthArguments(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


def argument_summary(value: object) -> str:
    if type(value) is dict:
        return f"object:{len(value)}"
    return "non-object"


def validate_arguments(value: object, schema: type[BaseModel], limit: int, depth: int) -> BaseModel:
    remaining = limit

    def charge(size: int) -> None:
        nonlocal remaining
        remaining -= size
        if remaining < 0:
            raise GuardrailError(ErrorCode.REQUEST_TOO_LARGE)

    def walk(item: object, level: int) -> None:
        if type(item) is str:
            if len(item) > remaining:
                raise GuardrailError(ErrorCode.REQUEST_TOO_LARGE)
            charge(len(json.dumps(item, ensure_ascii=False).encode("utf-8")))
        elif type(item) is dict or type(item) is list:
            if level > depth:
                raise GuardrailError(ErrorCode.INVALID_TOOL_ARGUMENTS)
            charge(2 + max(0, len(item) - 1))
            if type(item) is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise GuardrailError(ErrorCode.INVALID_TOOL_ARGUMENTS)
                    walk(key, level)
                    charge(1)
                    walk(child, level + 1)
            else:
                for child in item:
                    walk(child, level + 1)
        elif item is None or type(item) in (bool, int, float):
            if isinstance(item, float) and not math.isfinite(item):
                raise GuardrailError(ErrorCode.INVALID_TOOL_ARGUMENTS)
            charge(len(json.dumps(item, allow_nan=False)))
        else:
            raise GuardrailError(ErrorCode.INVALID_TOOL_ARGUMENTS)

    try:
        walk(value, 1)
        if type(value) is not dict or schema.model_config.get("extra") != "forbid":
            raise GuardrailError(ErrorCode.INVALID_TOOL_ARGUMENTS)
        return schema.model_validate(value, strict=True)
    except (ValidationError, ValueError, RecursionError):
        raise GuardrailError(ErrorCode.INVALID_TOOL_ARGUMENTS) from None
