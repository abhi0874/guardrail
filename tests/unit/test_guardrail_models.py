from uuid import uuid4

from mcp_agent_server.guardrails.models import GuardrailRequest


def test_only_server_correlation_and_metadata_are_serialized() -> None:
    request = GuardrailRequest(
        connection_id=uuid4(), tool_name="health", arguments={"token": "private"}
    )
    assert request.transport == "stdio"
    assert set(request.model_dump()) == {"connection_id", "request_id", "transport"}
    assert "private" not in repr(request)
    assert (
        GuardrailRequest(
            connection_id=request.connection_id, tool_name="health", arguments={}
        ).request_id
        != request.request_id
    )
