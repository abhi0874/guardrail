"""Acceptance checks for the passive MCP observation and receipt classifiers."""

from evidence_scan.detector import Observation
from evidence_scan.detector import classify as classify_observation
from receipt_scan.detector import classify as classify_receipt


def test_observer_distinguishes_match_divergence_and_missing_evidence():
    complete = Observation(
        expected=(),
        actual=(),
        expected_grants=(),
        consumed_grants=(),
        expected_audit=(),
        actual_audit=(),
        private_literals=(),
        returned_text=(),
        complete=True,
    )
    assert classify_observation(complete).verdict == "not_observed"
    different = complete.model_copy(update={"actual_audit": ("unexpected-event",)})
    assert classify_observation(different).verdict == "confirmed"
    missing = complete.model_copy(update={"actual_audit": None})
    assert classify_observation(missing).verdict == "indeterminate"


def test_receipt_classifier_needs_complete_independent_channels():
    facts = dict(
        intents=[],
        calls=[],
        operations=[],
        audit=[],
        attempts=[],
        effects=[],
        foreign_keys_ok=True,
        complete=True,
    )
    assert classify_receipt(facts).verdict == "not_observed"
    assert classify_receipt({**facts, "effects": None}).verdict == "indeterminate"
    assert classify_receipt({**facts, "foreign_keys_ok": False}).verdict == "confirmed"
