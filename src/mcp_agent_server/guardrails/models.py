from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from mcp_agent_server.errors import ErrorCode, PublicError


class GuardrailRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)
    request_id: UUID = Field(default_factory=uuid4)
    connection_id: UUID
    transport: Literal["stdio", "streamable-http"] = "stdio"
    tool_name: object = Field(repr=False, exclude=True)
    arguments: object = Field(repr=False, exclude=True)


class Validation(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNCHECKED = "unchecked"


class Status(StrEnum):
    NOT_EXECUTED = "not_executed"
    SUCCEEDED = "succeeded"
    REPLAYED = "replayed"
    DISPATCH_FAILED = "dispatch_failed"
    INTERRUPTED = "interrupted"


class GuardrailDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    allowed: bool
    validation: Validation
    reason: ErrorCode | None
    explanation: str


class GuardrailExecution(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    request_id: UUID
    decision: GuardrailDecision
    status: Status
    duration_ms: float = Field(ge=0, allow_inf_nan=False)
    error: PublicError | None
