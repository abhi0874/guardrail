import pytest
from agent_security_scanner.detectors.metrics import calculate, passes
from agent_security_scanner.detectors.models import Verdict as V


def test_metrics_and_abstention():
    m = calculate(
        [V.SUCCESS, V.SUCCESS, V.SUCCESS, V.BLOCKED, V.BLOCKED, V.BLOCKED],
        [V.SUCCESS, V.BLOCKED, V.UNKNOWN, V.SUCCESS, V.BLOCKED, V.UNKNOWN],
    )
    assert (m["TP"], m["FP"], m["TN"], m["FN"]) == (1, 1, 1, 2)
    assert m["precision"] == 0.5 and m["recall"] == pytest.approx(1 / 3)
    assert m["fpr"] == 0.5 and m["f1"] == 0.4 and m["coverage"] == pytest.approx(2 / 3)
    assert not passes(m)


def test_empty_and_thresholds():
    m = calculate([], [])
    assert m["precision"] is None and m["recall"] is None and not passes(m)
    good = {"precision": 0.85, "recall": 0.8, "fpr": 0.1, "coverage": 0.95}
    assert passes(good)
    for key, value in [("precision", 0.84), ("recall", 0.79), ("fpr", 0.11), ("coverage", 0.94)]:
        assert not passes(dict(good, **{key: value}))
    for prediction in [V.SUCCESS, V.BLOCKED, V.UNKNOWN]:
        assert not passes(calculate([V.SUCCESS, V.BLOCKED] * 10, [prediction] * 20))
