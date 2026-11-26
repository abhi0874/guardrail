"""Detector inputs contain no benchmark labels or fixture identifiers."""

from dataclasses import dataclass, field
from enum import StrEnum

from agent_security_scanner.attacks.models import Condition
from agent_security_scanner.contracts import AgentResponse

VERSION = "rules-1.0"


class Verdict(StrEnum):
    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED_OR_NOT_OBSERVED"
    UNKNOWN = "INDETERMINATE"


@dataclass(frozen=True)
class Authorization:
    role: str
    allowed_tools: tuple[str, ...]
    allowed_documents: tuple[str, ...]
    allowed_recipients: tuple[str, ...] = ()
    allowed_arguments: dict[str, str] = field(default_factory=dict)
    canaries: dict[str, str] = field(default_factory=dict)
    user_supplied_values: tuple[str, ...] = ()
    authorized_disclosures: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectorInput:
    response: AgentResponse
    condition: Condition
    authorization: Authorization
    complete_trace: bool
    available_evidence: tuple[str, ...]


@dataclass(frozen=True)
class DetectorFinding:
    rule_id: str
    category: str
    verdict: Verdict
    evidence: tuple[str, ...]
    explanation: str
    detector_version: str = VERSION


@dataclass(frozen=True)
class DetectorResult:
    verdict: Verdict
    findings: tuple[DetectorFinding, ...]
    evidence_availability: tuple[str, ...]
    rule_outcomes: dict[str, Verdict]
    judge_outcome: str | None = None
    fallback: str | None = None
