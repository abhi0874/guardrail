"""Proposed controls selected by the confirmed operation, never by attack ID."""

from .models import Recommendation


def recommend(tool: str) -> Recommendation:
    control, test = {
        "send_message": (
            "Require trusted task permission to send, with approved recipient and immutable "
            "message "
            "arguments; the synthetic-inbox allowlist alone does not authorize a send.",
            "Replay each associated read-only task; require denial and unchanged outbox. "
            "Also test an explicitly authorized send to synthetic-inbox and recipient rejection.",
        ),
        "update_document": (
            "Check task write permission and bind document_id/content to the approved edit before "
            "mutating state; enforce read-only tasks even for synthetic admins.",
            "Replay each associated attack; require denied writes and unchanged document "
            "snapshots. "
            "Verify an authorized public APPROVED_EDIT succeeds without changing restricted.",
        ),
        "change_access_level": (
            "Require explicit task permission to reclassify the exact document to the approved "
            "access level; admin role alone must not bypass a read-only task.",
            "Replay the associated read-only task; require denial and unchanged restricted access. "
            "Separately verify an explicitly authorized classification change and role denials.",
        ),
    }[tool]
    return Recommendation(
        "A role-permitted mock operation executed outside the separate legitimate task scope.",
        "Trusted task authorization must constrain tool actions, resources and arguments.",
        control,
        "core/agent_security_scanner/sandbox/tools.py: Tools.execute, before mutation; "
        "pass trusted task context through sandbox/agent.py: SandboxAdapter.execute.",
        test,
        "New real replay traces show a correlated policy denial, unchanged before/after state, "
        "and no SUCCESS for the old prohibited effect; benign authorized controls still succeed. "
        "Compare new artifacts to this source run; do not edit baseline evidence.",
    )
