"""Public errors carry a fixed code and message, independent of the exception cause."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class ErrorCode(StrEnum):
    DOCUMENT_NOT_FOUND = "document_not_found"
    FETCH_DESTINATION_DENIED = "fetch_destination_denied"
    FETCH_DNS_UNSAFE = "fetch_dns_unsafe"
    FETCH_RESPONSE_REJECTED = "fetch_response_rejected"
    FETCH_RESPONSE_TOO_LARGE = "fetch_response_too_large"
    FETCH_TIMEOUT = "fetch_timeout"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    OUTPUT_BLOCKED = "output_blocked"
    OUTPUT_UNSAFE = "output_unsafe"
    OUTPUT_LIMIT = "output_limit"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    CONFIGURATION = "invalid_configuration"
    INTERNAL = "internal_error"
    INVALID_POLICY = "invalid_policy"
    POLICY_DENIED = "policy_denied"
    PRINCIPAL_DENIED = "principal_not_permitted"
    CONSTRAINT_DENIED = "argument_constraint_violation"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_USED = "approval_consumed"
    APPROVAL_REVOKED = "approval_revoked"
    INVALID_TOOL_ARGUMENTS = "invalid_tool_arguments"
    REQUEST_TOO_LARGE = "request_too_large"
    UNKNOWN_TOOL = "unknown_tool"
    TOOL_NOT_PERMITTED = "tool_not_permitted"
    AUDIT_UNAVAILABLE = "audit_unavailable"
    AUDIT_INTEGRITY = "audit_integrity_failure"
    TOOL_EXECUTION_FAILED = "tool_execution_failed"

    IDEMPOTENCY_KEY_REQUIRED = "idempotency_key_required"
    INVALID_IDEMPOTENCY_KEY = "invalid_idempotency_key"
    IDEMPOTENCY_KEY_CONFLICT = "idempotency_key_conflict"
    OPERATION_IN_PROGRESS = "operation_in_progress"
    OPERATION_OUTCOME_UNKNOWN = "operation_outcome_unknown"
    STATE_CHANGE_FAILED = "state_change_failed"
    IDEMPOTENCY_EVIDENCE_INVALID = "idempotency_evidence_invalid"


class PublicError(BaseModel):
    model_config = ConfigDict(frozen=True)
    code: ErrorCode
    message: str
    retryable: bool


class ApplicationError(Exception):
    """Subclasses expose only fixed, safe fields across the application boundary."""

    public: PublicError

    def __init__(self) -> None:
        super().__init__(self.public.message)


class ConfigurationError(ApplicationError):
    public = PublicError(
        code=ErrorCode.CONFIGURATION, message="Invalid server configuration.", retryable=False
    )


class InternalError(ApplicationError):
    public = PublicError(
        code=ErrorCode.INTERNAL,
        message="The server could not complete the operation.",
        retryable=False,
    )


_MESSAGES = {
    ErrorCode.RATE_LIMIT_EXCEEDED: "Rate limit reached.",
    ErrorCode.OUTPUT_LIMIT: "The result exceeds the output limit.",
    ErrorCode.OUTPUT_UNSAFE: "The result could not be represented safely.",
    ErrorCode.OUTPUT_BLOCKED: "The returned content was blocked.",
    ErrorCode.DEPENDENCY_UNAVAILABLE: "The approved dependency is unavailable.",
    ErrorCode.FETCH_TIMEOUT: "The fetch deadline expired.",
    ErrorCode.FETCH_RESPONSE_TOO_LARGE: "The response exceeds the byte limit.",
    ErrorCode.FETCH_RESPONSE_REJECTED: "The endpoint returned an unsupported response.",
    ErrorCode.FETCH_DNS_UNSAFE: "The destination address is not permitted.",
    ErrorCode.FETCH_DESTINATION_DENIED: "Select an approved HTTPS destination.",
    ErrorCode.DOCUMENT_NOT_FOUND: "Select an approved document ID.",
    ErrorCode.IDEMPOTENCY_EVIDENCE_INVALID: "Original evidence could not be verified.",
    ErrorCode.STATE_CHANGE_FAILED: "The operation stopped before dispatch.",
    ErrorCode.OPERATION_OUTCOME_UNKNOWN: "The outcome requires reconciliation.",
    ErrorCode.OPERATION_IN_PROGRESS: "The operation is pending.",
    ErrorCode.IDEMPOTENCY_KEY_CONFLICT: "This key is bound to a different operation context.",
    ErrorCode.INVALID_IDEMPOTENCY_KEY: "Use 1 to 96 ASCII letters, digits, underscores or hyphens.",
    ErrorCode.IDEMPOTENCY_KEY_REQUIRED: "Supply an idempotency key for this operation.",
    ErrorCode.INVALID_TOOL_ARGUMENTS: "Use the declared tool schema and nesting limit.",
    ErrorCode.REQUEST_TOO_LARGE: "Reduce the encoded argument size.",
    ErrorCode.UNKNOWN_TOOL: "Select a tool declared by the server.",
    ErrorCode.TOOL_NOT_PERMITTED: "No policy rule permits this tool.",
    ErrorCode.INVALID_POLICY: "A valid local authorization policy is required.",
    ErrorCode.POLICY_DENIED: "The policy denies this operation.",
    ErrorCode.PRINCIPAL_DENIED: "The trusted principal lacks permission.",
    ErrorCode.CONSTRAINT_DENIED: "Arguments fall outside the authorized constraints.",
    ErrorCode.APPROVAL_REQUIRED: "A trusted operator approval is required.",
    ErrorCode.APPROVAL_INVALID: "The approval is invalid for this operation.",
    ErrorCode.APPROVAL_EXPIRED: "The approval has expired.",
    ErrorCode.APPROVAL_USED: "The approval was already consumed.",
    ErrorCode.APPROVAL_REVOKED: "The approval was revoked.",
    ErrorCode.AUDIT_UNAVAILABLE: "Required auditing is unavailable. Dispatch was denied.",
    ErrorCode.AUDIT_INTEGRITY: "Dispatch finished but its outcome could not be durably audited.",
    ErrorCode.TOOL_EXECUTION_FAILED: "Tool dispatch failed.",
}


class GuardrailError(ApplicationError):
    def __init__(self, code: ErrorCode) -> None:
        self.public = PublicError(code=code, message=_MESSAGES[code], retryable=False)
        super().__init__()
