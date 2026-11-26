"""One schema registry generated from the same Pydantic response models."""

import json
from typing import Any

from pydantic import TypeAdapter

from . import models as m

MODELS: dict[str, type[m.Model]] = {
    "overview": m.Overview,
    "scan-list": m.ScanList,
    "scan-summary": m.ScanSummary,
    "attack-list": m.AttackList,
    "attack-summary": m.AttackSummary,
    "attack-detail": m.AttackDetail,
    "detector": m.Detector,
    "finding-list": m.FindingList,
    "security-finding": m.SecurityFinding,
    "structured-report": m.StructuredReport,
    "export-manifest": m.Manifest,
    "health": m.Health,
    "error": m.ErrorResponse,
}


def encoded(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def schemas() -> dict[str, dict[str, Any]]:
    values = {name: model.model_json_schema(mode="serialization") for name, model in MODELS.items()}
    values["trace-event"] = TypeAdapter(m.TraceEvent).json_schema(mode="serialization")
    for name, schema in values.items():
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = "urn:agent-security-scanner:api:v1:" + name
    return dict(sorted(values.items()))


def name_for(model: m.Model) -> str:
    return next(name for name, cls in MODELS.items() if type(model) is cls)
