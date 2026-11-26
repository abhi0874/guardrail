from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from mcp_agent_server.errors import ErrorCode
from mcp_agent_server.guardrails.models import Status, Validation


class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    event_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    timestamp: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    connection_id: UUID
    tool_name: str
    phase: Literal["pre", "post", "denied"]
    allowed: bool
    validation: Validation
    status: Status
    error_code: ErrorCode | None
    duration_ms: float = Field(ge=0, allow_inf_nan=False)
    argument_summary: str
    parent_event_id: UUID | None = None
    policy_digest: str | None = None
    principal: str | None = None
    approval_required: bool | None = None
    approval_ref: UUID | None = None

    @field_validator("timestamp")
    @classmethod
    def normalize_utc(cls, timestamp: datetime) -> datetime:
        return timestamp.astimezone(UTC)
