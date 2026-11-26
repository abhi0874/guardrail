"""Trusted request bindings and a deliberately narrow, opt-in receipt format."""

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel

from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.approval import Binding
from mcp_agent_server.resilience.models import Safety


class State(StrEnum):
    RESERVED = "RESERVED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED_BEFORE_EFFECT = "FAILED_BEFORE_EFFECT"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class Decision(StrEnum):
    NEW = "new"
    REPLAY = "replay"
    PENDING = "in_progress"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"
    DENIED = "denied"


@dataclass(frozen=True)
class IdempotencyRequest:
    key_digest: str
    binding: Binding
    safety: Safety = field(default=Safety.UNSAFE_WRITE, init=False)

    @classmethod
    def create(cls, key: object, binding: Binding) -> "IdempotencyRequest":
        if key is None:
            raise GuardrailError(ErrorCode.IDEMPOTENCY_KEY_REQUIRED)
        if type(key) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", key):
            raise GuardrailError(ErrorCode.INVALID_IDEMPOTENCY_KEY)
        return cls(hashlib.sha256(key.encode("ascii")).hexdigest(), binding)


@dataclass(frozen=True)
class IdempotencyRecord:
    operation_id: str
    key_digest: str
    request_id: str
    binding: Binding
    state: State
    pre_id: str
    post_id: str | None
    created: float
    updated: float
    expires: float
    completed: float | None
    receipt: str | None
    error: str | None


class ReceiptCodec(Protocol):
    @property
    def total_seconds(self) -> float: ...
    def encode(self, data: object) -> str: ...
    def response(self, receipt: str, replay: bool) -> dict[str, object]: ...


@dataclass(frozen=True)
class Mutation:
    """Only boolean and integer fields explicitly approved by the tool author are cacheable."""

    public_fields: tuple[str, ...]
    total_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not self.public_fields or len(set(self.public_fields)) != len(self.public_fields):
            raise ValueError("Declare distinct public receipt fields")
        if not math.isfinite(self.total_seconds) or not 0 < self.total_seconds <= 300:
            raise ValueError("Invalid mutation deadline")

    def encode(self, data: object) -> str:
        if isinstance(data, BaseModel):
            data = data.model_dump(mode="json")
        if not isinstance(data, dict):
            raise ValueError("Expected a structured receipt")
        projected: dict[str, int | bool] = {}
        for name in self.public_fields:
            value = data.get(name)
            if (
                not isinstance(value, int)
                or type(value) not in (bool, int)
                or abs(value) > 2**53 - 1
            ):
                raise ValueError("Invalid public receipt")
            projected[name] = value
        receipt = json.dumps(projected, sort_keys=True, separators=(",", ":"))
        if len(receipt) > 4096:
            raise ValueError("Receipt exceeds limit")
        return receipt

    def response(self, receipt: str, replay: bool) -> dict[str, object]:
        data = json.loads(receipt)
        if self.encode(data) != receipt:
            raise ValueError("Invalid stored receipt")
        return {
            "structuredContent": data,
            "content": [{"type": "text", "text": receipt}],
            "_meta": {"mcp-agent-server/replayed": replay},
        }
