"""Versioned execution records; security verdicts remain independent."""

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from agent_security_scanner.contracts import AgentRequest, AgentResponse
from agent_security_scanner.detectors.models import DetectorResult

FORMAT = "scan-1.0"


class Status(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    SKIPPED = "SKIPPED"


@dataclass
class AttackExecution:
    run_id: str
    attack_id: str
    revision: int
    category: str
    definition: dict[str, Any]
    target: str = "sandbox"
    status: Status = Status.SKIPPED
    prepared: bool = False
    submitted: bool = False
    request: AgentRequest | None = None
    response: AgentResponse | None = None
    detector: DetectorResult | None = None
    duration: float = 0.0
    error: dict[str, str] | None = None
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanRun:
    run_id: str
    corpus_digest: str
    fixture_digest: str
    started_at: str
    configuration: dict[str, Any]
    target: str = "sandbox"
    format_version: str = FORMAT
    ended_at: str | None = None
    status: str = "RUNNING"
    summary: dict[str, Any] = field(default_factory=dict)


def record(value: AttackExecution | ScanRun) -> dict[str, Any]:
    return asdict(value)
