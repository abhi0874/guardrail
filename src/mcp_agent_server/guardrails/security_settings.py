"""Closed rule profiles and bounded operator inputs. No operator-supplied regex executes."""

import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class OutputSettings(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", hide_input_in_errors=True, allow_inf_nan=False
    )
    profile: Literal["v1"] = "v1"
    literals: tuple[SecretStr, ...] = Field(default=(), max_length=32, repr=False)
    patterns: tuple[Literal["provider-key", "bearer", "aws-key"], ...] = Field(
        default=("provider-key", "bearer", "aws-key"), max_length=3
    )
    max_bytes: int = Field(default=131072, ge=512, le=1048576)
    max_depth: int = Field(default=12, ge=3, le=32)
    max_text: int = Field(default=32768, ge=128, le=262144)
    max_items: int = Field(default=2048, ge=16, le=8192)

    @field_validator("literals", "patterns", mode="before")
    @classmethod
    def array(cls, value: object) -> object:
        if isinstance(value, str):
            if len(value) > 32768:
                raise ValueError("Oversized rule configuration")
            return json.loads(value)
        return value

    @field_validator("literals")
    @classmethod
    def valid_literals(cls, values: tuple[SecretStr, ...]) -> tuple[SecretStr, ...]:
        for item in values:
            s = item.get_secret_value()
            if not 4 <= len(s) <= 256 or not s.isprintable() or s in "[REDACTED]":
                raise ValueError("Invalid redaction literal")
        return values


class RateSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    connection_capacity: Annotated[int, Field(ge=1, le=100000)] = 100
    global_capacity: Annotated[int, Field(ge=1, le=1000000)] = 1000
    connection_refill: Annotated[float, Field(ge=0.001, le=100000)] = 20
    global_refill: Annotated[float, Field(ge=0.001, le=1000000)] = 200
    max_connections: Annotated[int, Field(ge=1, le=8192)] = 1024
    retention: Annotated[float, Field(ge=1, le=86400)] = 300
