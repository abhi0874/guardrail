import copy
import json
from dataclasses import replace

import pytest
from agent_security_scanner.contracts import EventType, TraceEvent
from agent_security_scanner.detectors.models import Verdict
from agent_security_scanner.detectors.rules import evaluate
from agent_security_scanner.detectors.validation import ROOT, detector_input


def case():
    value = json.loads((ROOT / "development/reader-restricted-0.json").read_text())
    return detector_input(value["input"])


def test_effect_and_references():
    result = evaluate(case())
    assert result.verdict == Verdict.SUCCESS and len(result.evidence) == 2
    assert "successful" in result.explanation
    assert result == evaluate(case())


def test_blocked_missing_and_contradictory():
    data = case()
    events = data.response.events
    denied = TraceEvent(EventType.ERROR, 2, {"call_id": "call-1", "message": "Denied"})
    assert (
        evaluate(
            replace(data, response=replace(data.response, events=events[:2] + (denied,)))
        ).verdict
        == Verdict.BLOCKED
    )
    assert (
        evaluate(replace(data, response=replace(data.response, events=events[:2]))).verdict
        == Verdict.UNKNOWN
    )
    contradiction = TraceEvent(EventType.ERROR, 4, {"call_id": "call-1", "message": "Denied"})
    assert (
        evaluate(
            replace(data, response=replace(data.response, events=events + (contradiction,)))
        ).verdict
        == Verdict.UNKNOWN
    )
    assert evaluate(replace(data, available_evidence=())).verdict == Verdict.UNKNOWN


def test_authorized_and_wrong_target():
    data = case()
    auth = replace(
        data.authorization,
        role="admin",
        allowed_tools=("read_document",),
        allowed_documents=("restricted",),
    )
    assert evaluate(replace(data, authorization=auth)).verdict == Verdict.BLOCKED
    payload = copy.deepcopy(data.response.events[2].payload)
    payload["result"]["document_id"] = "public"
    events = list(data.response.events)
    events[2] = replace(events[2], payload=payload)
    assert (
        evaluate(replace(data, response=replace(data.response, events=tuple(events)))).verdict
        == Verdict.UNKNOWN
    )


@pytest.mark.parametrize("sink", ["answer", "retrieval", "user", "authorized", "absent"])
def test_canary_sinks(sink):
    data = case()
    marker = "SYNTHETIC_CANARY_RESTRICTED_001"
    condition = copy.deepcopy(data.condition)
    condition.update(evidence="final_answer", marker=marker)
    events = ()
    if sink == "retrieval":
        events = (TraceEvent(EventType.RETRIEVED_DOCUMENT, 0, {"content": marker}),)
    if sink == "user":
        events = (TraceEvent(EventType.MESSAGE, 0, {"role": "user", "content": marker}),)
    auth = replace(
        data.authorization, authorized_disclosures=(marker,) if sink == "authorized" else ()
    )
    response = replace(
        data.response,
        events=events,
        final_answer=marker if sink in ["answer", "user", "authorized"] else "safe",
    )
    verdict = evaluate(
        replace(
            data,
            response=response,
            condition=condition,
            authorization=auth,
            available_evidence=("final_answer",),
        )
    ).verdict
    assert verdict == (
        {"answer": Verdict.SUCCESS, "user": Verdict.UNKNOWN}.get(sink, Verdict.BLOCKED)
    )


@pytest.mark.parametrize("family", ["reader-edit", "staff-access", "reader-send", "admin-target"])
def test_real_effect_channels(family):
    for variant, expected in [
        (0, Verdict.SUCCESS),
        (1, Verdict.SUCCESS),
        (2, Verdict.BLOCKED),
        (3, Verdict.BLOCKED),
    ]:
        row = json.loads((ROOT / f"development/{family}-{variant}.json").read_text())
        assert evaluate(detector_input(row["input"])).verdict == expected


def test_malformed_event():
    data = case()
    bad = TraceEvent(EventType.TOOL_CALL, 0, {"name": "read_document"})
    assert (
        evaluate(replace(data, response=replace(data.response, events=(bad,)))).verdict
        == Verdict.UNKNOWN
    )
