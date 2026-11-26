"""Serializable evidence envelopes, independent of transport and target runtime."""

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Protocol, TypeAlias

JSONValue: TypeAlias = None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


class EventType(StrEnum):
    MESSAGE = "message"
    RETRIEVED_DOCUMENT = "retrieved_document"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    ERROR = "error"


class ExecutionOutcome(StrEnum):
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    REJECTED = "rejected"


@dataclass(frozen=True)
class SyntheticDocument:
    document_id: str
    content: str
    provenance: JSONObject = field(default_factory=dict)


@dataclass(frozen=True)
class AgentRequest:
    request_id: str
    user_message: str
    documents: tuple[SyntheticDocument, ...] = ()
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id must not be empty")
        json.dumps(asdict(self), allow_nan=False)


@dataclass(frozen=True)
class TraceEvent:
    event_type: EventType
    sequence: int
    payload: JSONObject
    provenance: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("sequence must be nonnegative")
        json.dumps(asdict(self), allow_nan=False)


@dataclass(frozen=True)
class AgentResponse:
    request_id: str
    final_answer: str
    events: tuple[TraceEvent, ...]
    outcome: ExecutionOutcome

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id must not be empty")
        if any(
            a.sequence >= b.sequence for a, b in zip(self.events, self.events[1:], strict=False)
        ):
            raise ValueError("events must have strictly increasing sequence numbers")
        json.dumps(asdict(self), allow_nan=False)


class TargetAdapter(Protocol):
    async def execute(self, request: AgentRequest) -> AgentResponse:
        """Return a response with the same request ID and only observed evidence.

        Represent expected target, policy, transport and timeout failures as
        non-success outcomes with error events. Propagate cancellation and
        unexpected programming errors. Never fabricate unavailable trace events.
        """
        ...
