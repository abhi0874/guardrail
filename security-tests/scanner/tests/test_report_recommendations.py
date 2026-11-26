import pytest
from agent_security_scanner.reports.recommendations import recommend


@pytest.mark.parametrize(
    "tool,control,test",
    [
        ("send_message", "approved recipient", "unchanged outbox"),
        ("update_document", "document_id/content", "APPROVED_EDIT"),
        ("change_access_level", "read-only", "unchanged restricted access"),
    ],
)
def test_actionable_proposed_control(tool, control, test):
    r = recommend(tool)
    assert control in r.control and test in r.test
    assert "Tools.execute" in r.location
    assert "not implemented" in r.status
    assert "New real replay traces" in r.remediation_evidence
    assert "legitimate task" in r.problem and "Trusted task authorization" in r.boundary
