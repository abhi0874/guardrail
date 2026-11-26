import importlib
import json
from dataclasses import asdict

import pytest
from agent_security_scanner.contracts import (
    AgentRequest,
    AgentResponse,
    EventType,
    ExecutionOutcome,
    SyntheticDocument,
    TraceEvent,
)


def test_package_importability():
    for name in ("agent_security_scanner", "scanner_api"):
        module = importlib.import_module(name)
        assert module.__file__ is not None


def test_request_serialization():
    request = AgentRequest(
        "r1",
        "Summarize",
        (SyntheticDocument("doc1", "Synthetic text", {"source": "test-fixture"}),),
        {"comparison_id": "comparison1"},
    )
    wire = json.loads(json.dumps(asdict(request), allow_nan=False))
    assert wire["documents"][0]["provenance"]["source"] == "test-fixture"
    assert wire["metadata"]["comparison_id"] == "comparison1"
    assert AgentRequest("r2", "hello").documents == ()


def test_response_order_and_serialization():
    events = (
        TraceEvent(EventType.MESSAGE, 0, {"role": "user", "content": "hello"}),
        TraceEvent(EventType.RETRIEVED_DOCUMENT, 2, {"document_id": "d1", "content": "synthetic"}),
        TraceEvent(
            EventType.TOOL_CALL,
            3,
            {"call_id": "c1", "name": "test_only", "arguments": {"limit": 1}},
        ),
        TraceEvent(EventType.TOOL_RESULT, 4, {"call_id": "c1", "result": [True, None]}),
        TraceEvent(EventType.ERROR, 5, {"code": "target_error", "message": "synthetic failure"}),
    )
    response = AgentResponse("r1", "", events, ExecutionOutcome.ERROR)
    wire = json.loads(json.dumps(asdict(response), allow_nan=False))
    assert [event["sequence"] for event in wire["events"]] == [0, 2, 3, 4, 5]
    assert wire["events"][2]["event_type"] == "tool_call"
    assert wire["outcome"] == "error"
    assert AgentResponse("r2", "answer", (), ExecutionOutcome.SUCCESS).events == ()


@pytest.mark.parametrize("sequences", [(1, 0), (1, 1)])
def test_invalid_order(sequences):
    events = tuple(TraceEvent(EventType.MESSAGE, i, {}) for i in sequences)
    with pytest.raises(ValueError, match="strictly increasing"):
        AgentResponse("r1", "", events, ExecutionOutcome.SUCCESS)


def test_invalid_sequence_and_payload():
    with pytest.raises(ValueError, match="nonnegative"):
        TraceEvent(EventType.ERROR, -1, {})
    with pytest.raises(ValueError):
        TraceEvent(EventType.ERROR, 0, {"value": float("nan")})
    with pytest.raises(TypeError):
        TraceEvent(EventType.ERROR, 0, {"not_json": object()})
    with pytest.raises(ValueError, match="request_id"):
        AgentRequest(" ", "hello")
    with pytest.raises(ValueError, match="request_id"):
        AgentResponse("", "", (), ExecutionOutcome.ERROR)


def test_metadata_defaults_are_isolated():
    first, second = AgentRequest("r1", "one"), AgentRequest("r2", "two")
    first.metadata["test"] = True
    assert second.metadata == {}
