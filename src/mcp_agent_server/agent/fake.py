"""Scripted model turns. Business results always originate from MCP."""

import json
from collections.abc import Sequence

from .json_input import decode
from .models import Definition, Message, Provider, ProviderError, Reply


class FakeLLM:
    provider: Provider = "fake"

    def __init__(self, script: Sequence[str]):
        self._script = iter(script)

    async def respond(self, history: tuple[Message, ...], tools: tuple[Definition, ...]) -> Reply:
        raw = next(self._script, None)
        if raw is None or len(raw.encode()) > 32768:
            raise ProviderError("invalid_response")
        try:
            data = decode(raw)
            if isinstance(data, dict) and isinstance(data.get("calls"), list):
                data["calls"] = tuple(data["calls"])
            return Reply.model_validate(data)
        except (ValueError, RecursionError):
            raise ProviderError("invalid_response") from None


def scenario(name: str) -> FakeLLM:
    search = ("search_documents", {"query": "approval"})
    read = ("read_document", {"document_id": "approval-guide"})
    health: tuple[str, dict[str, str]] = ("health", {})
    sequences: dict[str, list[tuple[str, dict[str, str]]]] = {
        "answer": [],
        "search": [search],
        "search-read": [search, read],
        "note": [("write_note", {"title": "Agent demo", "body": "Synthetic note."})],
        "message": [
            (
                "send_message",
                {"recipient": "ops-lab", "subject": "Demo", "body": "Synthetic message."},
            )
        ],
        "unauthorized": [("issue_approval", {})],
        "rate": [health, health],
        "tool-error": [("read_document", {"document_id": "missing-doc"})],
        "suspicious": [read, ("issue_approval", {})],
        "limit": [health] * 33,
    }
    if name == "malformed":
        return FakeLLM(["{"])
    if name not in sequences:
        raise ValueError("Unknown scenario")
    script = [
        json.dumps({"calls": [{"name": tool, "arguments": args}]}) for tool, args in sequences[name]
    ]
    return FakeLLM([*script, '{"content":"Synthetic demonstration complete."}'])
