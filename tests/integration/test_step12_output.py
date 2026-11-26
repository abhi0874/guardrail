"""The real CLI never receives unsafe assembled provider text or tool arguments."""

import json
import logging
import sqlite3
from contextlib import closing
from functools import partial
from pathlib import Path
from typing import Any

import httpx2
import pytest

from mcp_agent_server.agent.__main__ import main
from mcp_agent_server.agent.connection import connect
from mcp_agent_server.agent.gemini import Gemini, GeminiConfig
from mcp_agent_server.agent.recording import replay

KEY = "synthetic_configured_credential_for_output_tests"


@pytest.mark.parametrize("case", ["two", "five", "one", "mixed", "structured", "legitimate"])
def test_real_cli_recording_and_replay_boundaries(
    case: str,
    audit_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    count = {"two": 2, "five": 5}.get(case, 1)
    payload: list[dict[str, Any]] = [
        {"text": KEY[i * len(KEY) // count : (i + 1) * len(KEY) // count]} for i in range(count)
    ]
    if case == "mixed":
        payload = [
            {"text": KEY[:18]},
            {
                "functionCall": {
                    "name": "write_note",
                    "args": {"title": "Synthetic", "body": "Must never commit."},
                }
            },
            {"text": KEY[18:]},
        ]
    elif case == "structured":
        payload = [
            {
                "functionCall": {
                    "name": "write_note",
                    "args": {"title": "Synthetic", "body": KEY},
                }
            }
        ]
    elif case == "legitimate":
        payload = [{"text": "Synthetic "}, {"text": "demonstration complete."}]
    calls = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(
            200,
            json={
                "candidates": [
                    {"content": {"role": "model", "parts": payload}, "finishReason": "STOP"}
                ]
            },
        )

    model = Gemini(
        GeminiConfig(model="gemini-synthetic", enabled=True, requests=3),
        environment={"GEMINI_API_KEY": KEY},
        transport=httpx2.MockTransport(handler),
    )

    def selected(_: GeminiConfig) -> Gemini:
        return model

    monkeypatch.setattr("mcp_agent_server.agent.gemini.Gemini", selected)
    monkeypatch.setattr(
        "mcp_agent_server.agent.connection.connect",
        partial(connect, audit_db=audit_db, isolated=True),
    )
    recording = tmp_path / "safe.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "agent",
            "run",
            "--provider",
            "gemini",
            "--gemini-live",
            "--gemini-model",
            "gemini-synthetic",
            "--allow-write",
            "write_note",
            "--record",
            str(recording),
        ],
    )
    caplog.set_level(logging.DEBUG)
    assert main() == (0 if case == "legitimate" else 1)
    stdout, stderr = capfd.readouterr()
    value = json.loads(stdout)
    assert KEY not in stdout + stderr + caplog.text + recording.read_text()
    assert len(calls) == model.counters.attempted == model.counters.successful == 1
    assert value["requests"] == {"attempted": 1, "successful": 1, "denied": 0}
    if case == "legitimate":
        assert value["answer"] == "Synthetic demonstration complete."
        assert value["recording"]["reason"] == "complete"
    else:
        assert value["answer"] is None
        assert value["recording"]["reason"] == "provider_error"
        assert value["recording"]["provider_error"] == "invalid_response"
        assert value["recording"]["events"] == []
    with closing(sqlite3.connect(audit_db)) as db:
        for table in ("notes", "operations", "approvals", "audit_events"):
            assert db.execute(f"select count(*) from {table}").fetchone()[0] == 0
    assert replay(recording).reason == value["recording"]["reason"]
    monkeypatch.setattr("sys.argv", ["agent", "replay", str(recording)])
    assert main() == 0
    stdout, stderr = capfd.readouterr()
    assert KEY not in stdout + stderr + caplog.text
    assert json.loads(stdout)["reason"] == value["recording"]["reason"]
    assert model.counters.attempted == 1
