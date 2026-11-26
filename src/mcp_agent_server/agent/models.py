"""Bounded provider contract. Only the runner constructs transport metadata."""

import json
from typing import Annotated, Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

Name = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
ToolName = Literal[
    "health", "search_documents", "read_document", "write_note", "send_message", "fetch_url"
]
TOOLS: tuple[ToolName, ...] = (
    "health",
    "search_documents",
    "read_document",
    "write_note",
    "send_message",
    "fetch_url",
)
Provider = Literal["fake", "ollama", "gemini"]
Failure = Literal[
    "invalid_response",
    "response_limit",
    "provider_unavailable",
    "provider_timeout",
    "model_unsupported",
    "remote_disabled",
    "budget_exhausted",
    "provider_auth",
    "provider_quota",
]


class ProviderError(Exception):
    def __init__(self, code: Failure):
        super().__init__(code)
        self.code = code


class Strict(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, allow_inf_nan=False, hide_input_in_errors=True
    )


class ToolCall(Strict, revalidate_instances="always"):
    name: Name
    arguments: dict[str, JsonValue] = Field(max_length=16)

    @field_validator("arguments")
    @classmethod
    def finite_arguments(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        # Validate every nested number without Pydantic's non-finite-to-null conversion.
        json.dumps(value, allow_nan=False)
        return value


class Definition(Strict):
    name: ToolName
    description: str = Field(max_length=1024)
    parameters: dict[str, JsonValue]


class Message(Strict):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(max_length=32768)
    calls: tuple[ToolCall, ...] = Field(default=(), max_length=8)
    tool_name: ToolName | None = None

    @model_validator(mode="after")
    def shape(self) -> Self:
        if (self.role == "tool") != (self.tool_name is not None) or (
            self.calls and self.role != "assistant"
        ):
            raise ValueError("Invalid message fields")
        return self


class Reply(Strict, revalidate_instances="always"):
    content: str = Field(default="", max_length=8192)
    calls: tuple[ToolCall, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def meaningful(self) -> Self:
        if not self.calls and not self.content.strip():
            raise ValueError("Empty reply")
        if len(self.model_dump_json().encode()) > 32768:
            raise ValueError("Oversized reply")
        return self


class Limits(Strict):
    turns: int = Field(default=8, ge=1, le=32)
    calls: int = Field(default=8, ge=1, le=32)
    messages: int = Field(default=32, ge=2, le=128)
    history_bytes: int = Field(default=65536, ge=512, le=262144)
    seconds: float = Field(default=30, gt=0, le=120)


class LLMClient(Protocol):
    @property
    def provider(self) -> Provider: ...
    async def respond(
        self, history: tuple[Message, ...], tools: tuple[Definition, ...]
    ) -> Reply: ...
