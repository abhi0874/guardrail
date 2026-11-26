"""Report 1.0 contracts. Source evidence stays in scan artifacts."""

import json
from dataclasses import asdict, dataclass
from typing import Any, Literal

VERSION = "report-1.0"
Confidence = Literal["High", "Medium", "Low"]
Band = Literal["Critical", "High", "Medium", "Low", "Informational"]


@dataclass(frozen=True)
class Dimension:
    name: str
    value: float
    maximum: float
    rationale: str


@dataclass(frozen=True)
class Severity:
    label: str
    score: float
    band: Band
    dimensions: list[Dimension]


@dataclass(frozen=True)
class EvidenceReference:
    artifact: str
    pointer: str
    attack_id: str
    revision: int
    purpose: str


@dataclass(frozen=True)
class Observation:
    attack_id: str
    revision: int
    category: str
    tool: str
    resource: str
    effect: str
    expected_boundary: str
    supplied_content: bool
    role: str
    evidence: list[EvidenceReference]
    reproduction: str
    expected_fixed_behavior: str


@dataclass(frozen=True)
class Recommendation:
    problem: str
    boundary: str
    control: str
    location: str
    test: str
    remediation_evidence: str
    status: str = "Proposed; not implemented or verified"


@dataclass(frozen=True)
class SecurityFinding:
    finding_id: str
    title: str
    categories: list[str]
    severity: Severity
    confidence: Confidence
    confidence_rationale: str
    tool: str
    resource: str
    grouping_rationale: str
    mechanism: str
    associated_attack_ids: list[str]
    observations: list[Observation]
    recommendation: Recommendation
    limitations: list[str]


@dataclass(frozen=True)
class AttackOutcome:
    attack_id: str
    revision: int
    category: str
    status: str
    submitted: bool
    verdict: str | None
    finding_id: str | None
    reasons: list[str]
    available_evidence: list[str]
    missing_evidence: list[str]
    next_verification: str | None
    source_pointer: str


@dataclass(frozen=True)
class SecurityReport:
    schema_version: str
    report_id: str
    source_scan_id: str
    source_target: str
    generated_at: str
    provenance: dict[str, Any]
    artifact_digests: dict[str, str]
    statistics: dict[str, Any]
    findings: list[SecurityFinding]
    unresolved_observations: list[AttackOutcome]
    blocked_attacks: list[AttackOutcome]
    execution_issues: list[AttackOutcome]
    attack_outcomes: list[AttackOutcome]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = json.loads(json.dumps(asdict(self), allow_nan=False))
        return value
