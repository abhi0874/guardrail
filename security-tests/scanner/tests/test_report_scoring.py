from dataclasses import replace

import pytest
from agent_security_scanner.reports.models import Dimension
from agent_security_scanner.reports.scoring import MAXIMA, band, calculate


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "Informational"),
        (0.1, "Low"),
        (3.9, "Low"),
        (4, "Medium"),
        (6.9, "Medium"),
        (7, "High"),
        (8.9, "High"),
        (9, "Critical"),
        (10, "Critical"),
    ],
)
def test_band_boundaries(value, expected):
    assert band(value) == expected


@pytest.mark.parametrize("value", [-1, 10.01, float("nan"), float("inf")])
def test_bad_scores(value):
    with pytest.raises(ValueError):
        band(value)


def test_dimensions_are_bounded_and_explainable():
    dimensions = [
        Dimension(k, maximum, maximum, "Observed in this fixture") for k, maximum in MAXIMA.items()
    ]
    assert calculate(dimensions).score == 10
    assert calculate([replace(d, value=0) for d in dimensions]).score == 0
    with pytest.raises(ValueError):
        calculate(dimensions + [dimensions[0]])
    with pytest.raises(ValueError):
        calculate([replace(dimensions[0], value=4.1), *dimensions[1:]])
    with pytest.raises(ValueError):
        calculate([replace(dimensions[0], rationale=""), *dimensions[1:]])
