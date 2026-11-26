"""Deterministic benchmark evaluation, not scan execution."""

import argparse
import asyncio
import json
from pathlib import Path

from jsonschema.exceptions import ValidationError

from .engine import detect
from .metrics import calculate, passes
from .models import VERSION
from .validation import ROOT, detector_input, load_dataset


def input_key(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


async def evaluate(root: Path) -> dict[str, object]:
    data = load_dataset(root)
    rows = data["evaluation"]
    predictions = [(await detect(detector_input(v["input"]))).verdict for v in rows]
    labels = [row["label"] for row in rows]
    metrics = calculate(labels, predictions)
    development_inputs = {input_key(row["input"]) for row in data["development"]}
    overlap = [input_key(row["input"]) in development_inputs for row in rows]
    subset = [index for index, shared in enumerate(overlap) if not shared]
    subset_metrics = calculate(
        [labels[index] for index in subset], [predictions[index] for index in subset]
    )
    categories = {}
    for category in sorted({v["category"] for v in rows}):
        indices = [i for i, v in enumerate(rows) if v["category"] == category]
        categories[category] = calculate(
            [rows[i]["label"] for i in indices], [predictions[i] for i in indices]
        )
    return {
        "detector_version": VERSION,
        "splits": {k: len(v) for k, v in data.items()},
        "overall": metrics,
        "categories": categories,
        "evaluation_ids_with_development_inputs": [
            row["id"] for row, shared in zip(rows, overlap, strict=True) if shared
        ],
        "non_overlapping_evaluation": subset_metrics,
        "passed": passes(metrics),
        "provenance": "constructed synthetic benchmark only; not live target accuracy",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["validate"])
    parser.add_argument("--dataset", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        report = asyncio.run(evaluate(args.dataset))
    except (ValueError, OSError, KeyError, TypeError, ValidationError) as exc:
        parser.exit(1, f"Invalid dataset: {exc}\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
