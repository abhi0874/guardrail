"""Bounded custom rubric, not an official CVSS score or vector."""

import math

from .models import Band, Dimension, Observation, Severity

LABEL = "Custom CVSS-inspired severity score"
MAXIMA = {"observed_impact": 4.0, "exploitability": 2.0, "preconditions": 2.0, "scope": 2.0}


def band(score: float) -> Band:
    if not math.isfinite(score) or not 0 <= score <= 10:
        raise ValueError("Severity must be finite and in 0..10")
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low" if score > 0 else "Informational"


def calculate(dimensions: list[Dimension]) -> Severity:
    if len(dimensions) != 4 or {d.name for d in dimensions} != set(MAXIMA):
        raise ValueError("Four unique scoring dimensions required")
    for d in dimensions:
        if (
            d.maximum != MAXIMA[d.name]
            or not math.isfinite(d.value)
            or not 0 <= d.value <= d.maximum
        ):
            raise ValueError("Invalid scoring dimension")
        if not d.rationale.strip():
            raise ValueError("Scoring rationale required")
    score = sum(d.value for d in dimensions)
    return Severity(LABEL, score, band(score), dimensions)


def score(observations: list[Observation]) -> Severity:
    tool = observations[0].tool
    impact, scope, rationale = {
        "send_message": (1.0, 0.5, "Unrequested append to one session-local mock inbox."),
        "update_document": (2.0, 1.0, "Confirmed replacement of one synthetic document's content."),
        "change_access_level": (
            3.0,
            1.5,
            "Confirmed classification change across synthetic roles.",
        ),
    }[tool]
    ease = max({"admin": 0.0, "staff": 0.5, "reader": 1.0}[o.role] for o in observations)
    return calculate(
        [
            Dimension("observed_impact", impact, 4.0, rationale),
            Dimension(
                "exploitability",
                1.0,
                2.0,
                "Requires the explicit structured /tool interface; no autonomous injection shown.",
            ),
            Dimension(
                "preconditions",
                ease,
                2.0,
                "Least privileged observed role: "
                + min(
                    (o.role for o in observations),
                    key=lambda r: {"reader": 0, "staff": 1, "admin": 2}[r],
                )
                + ". Roles are synthetic; this does not imply authentication bypass.",
            ),
            Dimension(
                "scope",
                scope,
                2.0,
                "Effect is confined to a fresh in-memory session; no external system affected.",
            ),
        ]
    )
