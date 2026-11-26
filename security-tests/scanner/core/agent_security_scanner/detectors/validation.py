"""Schema-checked benchmark ingestion with label-free detector conversion."""

import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from agent_security_scanner.contracts import AgentResponse, EventType, ExecutionOutcome, TraceEvent
from agent_security_scanner.paths import ROOT as PACKAGE_ROOT

from .models import Authorization, DetectorInput

ROOT = PACKAGE_ROOT / "data/detector_validation"


def detector_input(value: dict[str, Any]) -> DetectorInput:
    response = value["response"]
    return DetectorInput(
        AgentResponse(
            response["request_id"],
            response["final_answer"],
            tuple(
                TraceEvent(EventType(e["event_type"]), e["sequence"], e["payload"], e["provenance"])
                for e in response["events"]
            ),
            ExecutionOutcome(response["outcome"]),
        ),
        value["condition"],
        Authorization(**value["authorization"]),
        value["complete_trace"],
        tuple(value["available_evidence"]),
    )


def load_dataset(root: Path = ROOT) -> dict[str, list[dict[str, Any]]]:
    validator = Draft202012Validator(json.loads((root / "schema/trace.v1.schema.json").read_text()))
    manifest = json.loads((root / "manifest.json").read_text())
    ids: set[str] = set()
    families: dict[str, str] = {}
    result: dict[str, list[dict[str, Any]]] = {"development": [], "evaluation": []}
    discovered = set()
    for split in result:
        for path in sorted((root / split).glob("*.json")):
            value = json.loads(path.read_text())
            validator.validate(value)
            relative = str(path.relative_to(root))
            discovered.add(relative)
            if manifest["files"].get(relative) != hashlib.sha256(path.read_bytes()).hexdigest():
                raise ValueError(f"{path}: immutable benchmark hash mismatch")
            if value["id"] in ids or families.get(value["family"], split) != split:
                raise ValueError(f"{path}: duplicate ID or family crosses splits")
            ids.add(value["id"])
            families[value["family"]] = split
            detector_input(value["input"])
            result[split].append(value)
    if discovered != set(manifest["files"]):
        raise ValueError("Manifest/file mismatch")
    if len(result["development"]) < 40 or len(result["evaluation"]) < 100 or len(ids) < 150:
        raise ValueError("Insufficient split support")
    evaluation = result["evaluation"]
    if any(
        sum(v["label"] == label for v in evaluation) < 40
        for label in ["SUCCESS", "BLOCKED_OR_NOT_OBSERVED"]
    ):
        raise ValueError("Insufficient positive/negative support")
    if len({v["category"] for v in evaluation}) != 7:
        raise ValueError("Missing evaluation categories")
    return result
