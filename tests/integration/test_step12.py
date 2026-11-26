"""Real MCP with a fake Gemini HTTP boundary; passive replay traps all side effects."""

import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from typing import Any

import httpx2
import pytest

from mcp_agent_server.agent.connection import connect
from mcp_agent_server.agent.demo import FILES, execute
from mcp_agent_server.agent.gemini import Gemini, GeminiConfig
from mcp_agent_server.agent.recording import replay
from mcp_agent_server.agent.runner import run

from .http_support import client, listener

KEY = "synthetic_api_key_for_local_tests_only"


def reply(parts: list[dict[str, Any]]) -> dict[str, Any]:
    return {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP"}]}


@pytest.mark.asyncio
async def test_real_stdio_gemini_note_replay_and_private_recording(audit_db: Path) -> None:
    seen = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        if len(seen) < 3:
            return httpx2.Response(
                200,
                json=reply(
                    [
                        {
                            "functionCall": {
                                "name": "write_note",
                                "args": {"title": "Gemini fake HTTP", "body": "Synthetic note."},
                            }
                        }
                    ]
                ),
            )
        return httpx2.Response(200, json=reply([{"text": "Synthetic demonstration complete."}]))

    model = Gemini(
        GeminiConfig(model="gemini-synthetic", enabled=True, requests=3),
        environment={"GEMINI_API_KEY": KEY},
        transport=httpx2.MockTransport(handler),
    )
    marker = "PRIVATE_SYNTHETIC_PROMPT_NOT_FOR_RECORDING"
    async with connect(audit_db=audit_db, isolated=True) as c:
        result = await run(c, model, marker, allow_writes=frozenset({"write_note"}))
    assert result.recording.reason == "complete" and [
        e.replayed for e in result.recording.events
    ] == [False, True]
    assert model.counters.attempted == model.counters.successful == len(seen) == 3
    assert result.recording.provider == "gemini"
    assert (
        KEY not in result.recording.model_dump_json()
        and marker not in result.recording.model_dump_json()
    )
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("select count(*) from notes").fetchone()[0] == 1
        assert db.execute("select count(*) from operations").fetchone()[0] == 1
        assert [
            r[0] for r in db.execute("select decision from operation_attempts order by rowid")
        ] == ["new", "replay"]


@pytest.mark.asyncio
async def test_authenticated_http_gemini_cannot_approve_message(audit_db: Path) -> None:
    model = Gemini(
        GeminiConfig(model="gemini-synthetic", enabled=True, requests=3),
        environment={"GEMINI_API_KEY": KEY},
        transport=httpx2.MockTransport(
            lambda _: httpx2.Response(
                200,
                json=reply(
                    [
                        {
                            "functionCall": {
                                "name": "send_message",
                                "args": {
                                    "recipient": "ops-lab",
                                    "subject": "Synthetic",
                                    "body": "No authority from the model.",
                                },
                            }
                        }
                    ]
                ),
            )
        ),
    )
    async with listener(audit_db) as (url, clients, _):
        token, _ = clients.issue()
        async with client(url, token) as c:
            result = await run(
                c, model, "Synthetic request.", allow_writes=frozenset({"send_message"})
            )
    assert (
        result.recording.reason == "tool_error"
        and result.recording.events[-1].code == "approval_required"
    )
    assert model.counters.attempted == 1
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("select count(*) from approvals").fetchone()[0] == 0
        assert db.execute("select count(*) from operations").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_complete_demo_and_hard_passive_replay(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    assert await execute(directory) == 0
    assert all(replay(directory / name).provider == "fake" for name in FILES)
    before = {str(p): p.read_bytes() for p in directory.iterdir()}
    code = """
import os,sys
sys.dont_write_bytecode=True
def guard(event,args):
    if event.startswith('socket.') or event in {
        'subprocess.Popen','sqlite3.connect','os.remove','os.rename','os.mkdir'}:
        raise AssertionError(event)
    if event=='open' and args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
        raise AssertionError('write')
    if event=='import' and (args[0] in {
        'mcp','httpx','httpx2','sqlite3','google.genai',
        'mcp_agent_server.agent.gemini','mcp_agent_server.agent.ollama',
        'mcp_agent_server.agent.fake','mcp_agent_server.agent.runner',
        'mcp_agent_server.agent.connection'}):
        raise AssertionError(args[0])
sys.addaudithook(guard)
from mcp_agent_server.agent.demo import playback
print(playback(__import__('pathlib').Path(sys.argv[1])))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(directory)],
        capture_output=True,
        text=True,
        timeout=10,
        # Disable only child coverage startup: its atexit database write would violate
        # the intentional no-write guard, independently of passive replay behavior.
        env={
            **{k: v for k, v in os.environ.items() if not k.startswith("COVERAGE_")},
            "PYTHONDONTWRITEBYTECODE": "1",
            "GEMINI_API_KEY": KEY,
        },
    )
    assert result.returncode == 0 and not result.stderr
    assert KEY not in result.stdout and result.stdout.count("Recorded ") == 4
    assert before == {str(p): p.read_bytes() for p in directory.iterdir()}


@pytest.mark.asyncio
async def test_agent_fourth_turn_stops_at_actual_three_request_cap(audit_db: Path) -> None:
    requests = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(200, json=reply([{"functionCall": {"name": "health", "args": {}}}]))

    model = Gemini(
        GeminiConfig(model="gemini-synthetic", enabled=True, requests=3),
        environment={"GEMINI_API_KEY": KEY},
        transport=httpx2.MockTransport(handler),
    )
    async with connect(audit_db=audit_db, isolated=True) as c:
        result = await run(c, model, "Synthetic bounded run.")
    assert result.recording.reason == "provider_error"
    assert result.recording.provider_error == "budget_exhausted"
    assert len(result.recording.events) == len(requests) == model.counters.attempted == 3
    assert model.counters.denied == 1
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("select count(*) from audit_events where phase='post'").fetchone()[0] == 3
        assert db.execute("select count(*) from operations").fetchone()[0] == 0
