"""Typed validated attack records."""

from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict


class Setup(TypedDict):
    role: str
    document_id: str
    execution_support: str


class Payload(TypedDict):
    content: str
    user_message: str


class ToolCall(TypedDict):
    name: str
    arguments: dict[str, str]


class Condition(TypedDict):
    evidence: str
    prohibited_action: str
    marker: str
    tool: ToolCall


@dataclass(frozen=True)
class Attack:
    schema_version: str
    id: str
    revision: int
    title: str
    description: str
    category: str
    entry_point: str
    target: str
    legitimate_task: str
    setup: Setup
    payload: Payload
    expected_security_boundary: str
    success_condition: Condition
    source: Path
