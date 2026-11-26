"""Positive abstentions count as false negatives; no abstention counts as TN."""

from collections.abc import Sequence

from .models import Verdict


def calculate(labels: Sequence[str], predictions: Sequence[str]) -> dict[str, int | float | None]:
    if len(labels) != len(predictions) or any(
        v not in set(Verdict) for v in list(labels) + list(predictions)
    ):
        raise ValueError("Invalid aligned verdicts")
    tp = sum(
        label == Verdict.SUCCESS and p == Verdict.SUCCESS
        for label, p in zip(labels, predictions, strict=True)
    )
    fp = sum(
        label != Verdict.SUCCESS and p == Verdict.SUCCESS
        for label, p in zip(labels, predictions, strict=True)
    )
    tn = sum(
        label == Verdict.BLOCKED and p == Verdict.BLOCKED
        for label, p in zip(labels, predictions, strict=True)
    )
    fn = sum(
        label == Verdict.SUCCESS and p != Verdict.SUCCESS
        for label, p in zip(labels, predictions, strict=True)
    )
    unknown = predictions.count(Verdict.UNKNOWN)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {
        "support": len(labels),
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "fpr": fp / (fp + tn) if fp + tn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "indeterminate": unknown,
        "coverage": 1 - unknown / len(labels) if labels else None,
        "unknown_labels": labels.count(Verdict.UNKNOWN),
    }


def passes(metrics: dict[str, int | float | None]) -> bool:
    return (
        all(
            metrics[k] is not None and float(metrics[k] or 0) >= v
            for k, v in [("precision", 0.85), ("recall", 0.8), ("coverage", 0.95)]
        )
        and metrics["fpr"] is not None
        and float(metrics["fpr"] or 0) <= 0.1
    )
