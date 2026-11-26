"""Public api-1.0 contracts: explicit fields, bounded primitives and inert evidence."""

from typing import Annotated, Literal

from agent_security_scanner.contracts import ExecutionOutcome
from agent_security_scanner.detectors.models import Verdict as Verdict
from agent_security_scanner.reports.models import Band as Band
from agent_security_scanner.reports.models import Confidence as Confidence
from agent_security_scanner.reports.models import Recommendation
from agent_security_scanner.reports.scoring import band
from agent_security_scanner.runner.models import Status as Status
from pydantic import BaseModel, ConfigDict, Field, model_validator

VERSION: Literal["api-1.0"] = "api-1.0"
Count = Annotated[int, Field(ge=0, strict=True)]
Revision = Annotated[int, Field(ge=1, strict=True)]
Duration = Annotated[float, Field(ge=0, allow_inf_nan=False)]
Identifier = Annotated[str, Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=128)]
Hash = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ResourcePath = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)*\.(json|md)$")]
Category = Literal[
    "direct",
    "indirect",
    "poisoned_documents",
    "unauthorized_calls",
    "argument_tampering",
    "exfiltration",
    "privilege_escalation",
]
Role = Literal["reader", "staff", "admin"]
Access = Literal["public", "internal", "restricted"]
Tool = Literal[
    "search_documents", "read_document", "send_message", "update_document", "change_access_level"
]
EntryPoint = Literal["user_message", "retrieved_document"]
Timestamp = Annotated[
    str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
]


class Model(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        json_schema_serialization_defaults_required=True,
    )


class Versioned(Model):
    schema_version: Literal["api-1.0"] = VERSION


class Counts(Model):
    loaded: Count
    prepared: Count
    submitted: Count
    recorded_executions: Count
    completed: Count
    failed: Count
    timed_out: Count
    skipped: Count
    trace_events: Count
    successful_attack_executions: Count
    observed_effects: Count
    distinct_findings: Count
    blocked_or_not_observed: Count
    indeterminate: Count
    unevaluated: Count
    severity_distribution: dict[Band, Count]


class SourceProvenance(Model):
    scan_format: Literal["scan-1.0"]
    report_format: Literal["report-1.0"]
    report_id: Identifier
    report_generated_at: Timestamp
    artifact_digests: dict[str, Hash]
    corpus_digest: Hash
    fixture_digest: Hash
    scope: Literal["local_synthetic_sandbox"] = "local_synthetic_sandbox"


class ScanSummary(Versioned):
    scan_id: Identifier
    target: Literal["sandbox"]
    status: Literal["COMPLETED", "FAILED", "INTERRUPTED", "RUNNING"]
    started_at: Timestamp
    ended_at: Timestamp | None
    duration_seconds: Duration | None
    counts: Counts
    provenance: SourceProvenance
    limitations: list[str]


class Overview(Versioned):
    scope: Literal["local_synthetic_sandbox"] = "local_synthetic_sandbox"
    counts: Counts
    scan_ids: list[Identifier]
    limitations: list[str]


class ScanList(Versioned):
    total: Count
    items: list[ScanSummary]


class ToolCall(Model):
    name: Tool
    arguments: dict[str, str]


class Condition(Model):
    evidence: Literal["final_answer", "tool_call", "tool_result", "document_state", "outbox"]
    marker: str
    prohibited_action: str
    tool: ToolCall


class Setup(Model):
    role: Role
    document_id: Identifier
    execution_support: Literal["native_user_message", "requires_document_preparation"]


class Payload(Model):
    content: str
    user_message: str


class AttackDefinition(Model):
    schema_version: Literal["1.0"]
    id: Identifier
    revision: Revision
    title: str
    description: str
    category: Category
    entry_point: EntryPoint
    target: Literal["synthetic_sandbox"]
    legitimate_task: str
    setup: Setup
    payload: Payload
    expected_security_boundary: str
    success_condition: Condition


class EventProvenance(Model):
    source: Literal["sandbox", "synthetic-corpus-v1"]


class DocumentResult(Model):
    document_id: Identifier
    content: str
    access: Access


class Document(DocumentResult):
    source: Literal["synthetic-corpus-v1"]


class MessagePayload(Model):
    role: Literal["system", "user", "assistant"]
    content: str


class CallPayload(ToolCall):
    call_id: Identifier


class StoredMessage(Model):
    stored_message_index: Count


class ResultPayload(Model):
    call_id: Identifier
    result: Document | DocumentResult | StoredMessage | list[Identifier]


class ErrorPayload(Model):
    call_id: Identifier | None = None
    code: str
    message: str


class Event(Model):
    sequence: Count
    provenance: EventProvenance


class MessageEvent(Event):
    event_type: Literal["message"]
    payload: MessagePayload


class CallEvent(Event):
    event_type: Literal["tool_call"]
    payload: CallPayload


class ResultEvent(Event):
    event_type: Literal["tool_result"]
    payload: ResultPayload


class RetrievalEvent(Event):
    event_type: Literal["retrieved_document"]
    payload: Document


class ErrorEvent(Event):
    event_type: Literal["error"]
    payload: ErrorPayload


TraceEvent = Annotated[
    MessageEvent | CallEvent | ResultEvent | RetrievalEvent | ErrorEvent,
    Field(discriminator="event_type"),
]


class Response(Model):
    request_id: str
    final_answer: str
    events: list[TraceEvent]
    outcome: ExecutionOutcome

    @model_validator(mode="after")
    def ordered(self) -> "Response":
        sequences = [e.sequence for e in self.events]
        if sequences != sorted(set(sequences)):
            raise ValueError("Trace events must be strictly ordered")
        return self


class Request(Model):
    request_id: str
    user_message: str


class DetectorFinding(Model):
    rule_id: str
    category: str
    verdict: Verdict
    evidence: list[str]
    explanation: str
    detector_version: Literal["rules-1.0"]


class Detector(Model):
    verdict: Verdict
    findings: list[DetectorFinding]
    evidence_availability: list[str]
    rule_outcomes: dict[str, Verdict]
    judge_outcome: str | None
    fallback: str | None


class Authorization(Model):
    role: Role
    allowed_tools: list[Tool]
    allowed_documents: list[Identifier]
    allowed_recipients: list[Literal["synthetic-inbox"]]
    allowed_arguments: dict[str, str]
    canaries: dict[str, Identifier]
    user_supplied_values: list[str]
    authorized_disclosures: list[str]


class MockMessage(Model):
    recipient: Literal["synthetic-inbox"]
    message: str


class State(Model):
    role: Role
    documents: dict[Identifier, Document]
    outbox: list[MockMessage]


class EvidenceState(Model):
    authorization: Authorization | None
    prepared_state: State | None
    final_state: State | None
    unavailable_evidence: list[str]


class ExecutionError(Model):
    phase: str
    type: str
    message: str


class AttackSummary(Versioned):
    scan_id: Identifier
    attack_id: Identifier
    revision: Revision
    title: str
    category: Category
    entry_point: EntryPoint
    status: Status
    prepared: bool
    submitted: bool
    detector_verdict: Verdict | None
    duration: Duration
    event_count: Count
    finding_ids: list[Identifier]


class AttackDetail(AttackSummary):
    definition: AttackDefinition
    request: Request | None
    response: Response | None
    detector: Detector | None
    provenance: EvidenceState
    error: ExecutionError | None


class AttackList(Versioned):
    total: Count
    offset: Count
    limit: Annotated[int, Field(ge=1, le=256)]
    items: list[AttackSummary]


class Dimension(Model):
    name: Literal["observed_impact", "exploitability", "preconditions", "scope"]
    value: Annotated[float, Field(ge=0, le=4)]
    maximum: Annotated[float, Field(ge=2, le=4, json_schema_extra={"enum": [2.0, 4.0]})]
    rationale: str


class Severity(Model):
    label: Literal["Custom CVSS-inspired severity score"]
    score: Annotated[float, Field(ge=0, le=10)]
    band: Band
    dimensions: list[Dimension]

    @model_validator(mode="after")
    def consistent(self) -> "Severity":
        from agent_security_scanner.reports.models import Dimension as CoreDimension
        from agent_security_scanner.reports.scoring import calculate

        result = calculate([CoreDimension(**d.model_dump()) for d in self.dimensions])
        if self.score != result.score or self.band != band(self.score):
            raise ValueError("Inconsistent severity")
        return self


class EvidenceReference(Model):
    artifact: ResourcePath
    pointer: str
    source_pointer: str
    attack_id: Identifier
    revision: Revision
    purpose: str


class Observation(Model):
    attack_id: Identifier
    revision: Revision
    category: Category
    tool: Tool
    resource: Identifier
    effect: str
    expected_boundary: str
    supplied_content: bool
    role: Role
    evidence: list[EvidenceReference]
    reproduction: str
    expected_fixed_behavior: str


class SecurityFinding(Versioned):
    scan_id: Identifier
    finding_id: Identifier
    title: str
    categories: list[Category]
    severity: Severity
    confidence: Confidence
    confidence_rationale: str
    tool: Tool
    resource: Identifier
    grouping_rationale: str
    mechanism: str
    associated_attack_ids: list[Identifier]
    observations: list[Observation]
    recommendation: Recommendation
    limitations: list[str]


class FindingList(Versioned):
    total: Count
    items: list[SecurityFinding]


class AttackOutcome(Model):
    attack_id: Identifier
    revision: Revision
    category: Category
    status: Status
    submitted: bool
    verdict: Verdict | None
    finding_id: Identifier | None
    reasons: list[str]
    available_evidence: list[str]
    missing_evidence: list[str]
    next_verification: str | None
    artifact: ResourcePath


class StructuredReport(Versioned):
    report_id: Identifier
    source_scan_id: Identifier
    source_target: Literal["sandbox"]
    generated_at: Timestamp
    provenance: SourceProvenance
    counts: Counts
    findings: list[SecurityFinding]
    unresolved_observations: list[AttackOutcome]
    blocked_attacks: list[AttackOutcome]
    execution_issues: list[AttackOutcome]
    attack_outcomes: list[AttackOutcome]
    limitations: list[str]


class Resource(Model):
    path: ResourcePath
    endpoint: str | None
    schema_name: Identifier | None
    sha256: Hash
    bytes: Count
    media_type: Literal["application/json", "text/markdown"]


class Manifest(Versioned):
    export_format: Literal["static-1.0"] = "static-1.0"
    source_scan_id: Identifier
    source_report_id: Identifier
    source_report_version: Literal["report-1.0"]
    scope: Literal["local_synthetic_sandbox"] = "local_synthetic_sandbox"
    counts: Counts
    resources: list[Resource]
    schemas: dict[Identifier, ResourcePath]
    provenance: SourceProvenance
    static_replay_disclosure: str
    limitations: list[str]


class Health(Versioned):
    status: Literal["ok"] = "ok"
    mode: Literal["read_only_snapshot"] = "read_only_snapshot"


class ErrorResponse(Versioned):
    code: str
    message: str


BANDS: tuple[Band, ...] = ("Critical", "High", "Medium", "Low", "Informational")
