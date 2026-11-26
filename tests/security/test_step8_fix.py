import json
import math
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import httpx
import pytest
from integration.http_support import client, listener

from mcp_agent_server.agent.fake import FakeLLM
from mcp_agent_server.agent.models import (
    Definition,
    LLMClient,
    Message,
    ProviderError,
    Reply,
    ToolCall,
)
from mcp_agent_server.agent.ollama import Ollama
from mcp_agent_server.agent.runner import run
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.policy import load_policy
from mcp_agent_server.tools.models import Message as SimulatedMessage


@pytest.mark.asyncio
@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e9999"])
async def test_fake_rejects_nonfinite(number: str) -> None:
    raw = '{"calls":[{"name":"health","arguments":{"nested":[{"value":' + number + "}]}}]}"
    with pytest.raises(ProviderError, match="invalid_response"):
        await FakeLLM([raw]).respond((), ())


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["python", "fake", "ollama"])
async def test_entire_reply_rejected_before_approved_mutation(audit_db: Path, source: str) -> None:
    args = {"recipient": "ops-lab", "subject": "Audit", "body": "Synthetic"}
    valid = ToolCall(name="send_message", arguments=dict(args))
    raw = json.dumps(
        {
            "calls": [
                valid.model_dump(),
                {"name": "health", "arguments": {"nested": [{"x": math.nan}]}},
            ]
        }
    )

    class Unchecked(FakeLLM):
        async def respond(
            self, history: tuple[Message, ...], tools: tuple[Definition, ...]
        ) -> Reply:
            bad = ToolCall(name="health", arguments={})
            bad.arguments["nested"] = [{"x": math.inf}]
            return Reply.model_construct(content="", calls=(valid, bad))

    def native(req: httpx.Request) -> httpx.Response:
        wire = (
            {"capabilities": ["tools"]}
            if req.url.path == "/api/show"
            else {
                "model": "fixture",
                "done": True,
                "total_duration": math.nan,
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"function": valid.model_dump()}],
                },
            }
        )
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(wire).encode()))

    providers: dict[str, LLMClient] = {
        "python": Unchecked([]),
        "fake": FakeLLM([raw]),
        "ollama": Ollama("fixture", transport=httpx.MockTransport(native)),
    }
    async with listener(audit_db) as (url, registry, _):
        token, ref = registry.issue()
        gate = ApprovalGate(AuditStore(audit_db), load_policy())
        gate.issue(
            ref.authorization,
            "send_message",
            SimulatedMessage.model_validate(args),
            issuer="audit",
            ttl_seconds=60,
        )
        async with client(url, token) as c:
            result = await run(
                c, providers[source], "audit", allow_writes=frozenset({"send_message"})
            )
        assert result.recording.provider_error == "invalid_response" and not result.recording.events
        with gate.store.transaction() as db:
            assert db.execute("select count(consumed_event) from approvals").fetchone() == (0,)
            for table in ("notes", "operations", "audit_events"):
                assert db.execute(f"select count(*) from {table}").fetchone() == (0,)


@pytest.mark.parametrize(
    "version",
    [True, False, 1.0, "1", 2, 1],
    ids=["true", "false", "float", "string", "unsupported", "int"],
)
def test_replay_exact_version(tmp_path: Path, version: object) -> None:
    data = json.loads(Path("examples/search-read.json").read_bytes())
    data["version"] = version
    path = tmp_path / "version.json"
    path.write_text(json.dumps(data))
    code = """
import sys,runpy
hits=[]
active=True
blocked=('mcp.client','mcp_agent_server.agent.runner','mcp_agent_server.agent.fake',
         'mcp_agent_server.agent.ollama')
def guard(event,args):
    if not active: return
    if event.startswith(('socket.','sqlite3.','subprocess.')) or (
            event=='import' and args[0].startswith(blocked)):
        hits.append(event);raise AssertionError(event)
sys.addaudithook(guard)
sys.argv=['agent','replay',sys.argv[1]]
try: runpy.run_module('mcp_agent_server.agent',run_name='__main__')
finally:
    active=False  # Coverage saves its own SQLite database after replay exits.
    assert not hits
"""
    proc = subprocess.run(
        [sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=10
    )
    if type(version) is int and version == 1:
        assert proc.returncode == 0 and json.loads(proc.stdout) == data
    else:
        assert proc.returncode == 2 and not proc.stdout and "Traceback" not in proc.stderr


def test_cli_collision_before_any_dispatch(tmp_path: Path, audit_db: Path) -> None:
    AuditStore(audit_db)
    path = tmp_path / "capture"
    path.write_text("sentinel")
    for scenario, tool in [
        ("note", "write_note"),
        ("note", "write_note"),
        ("message", "send_message"),
    ]:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mcp_agent_server.agent",
                "run",
                "--scenario",
                scenario,
                "--allow-write",
                tool,
                "--record",
                str(path),
            ],
            env={**os.environ, "MCP_AGENT_AUDIT_DB": str(audit_db)},
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 2 and not proc.stdout and path.read_text() == "sentinel"
        with closing(sqlite3.connect(audit_db)) as db:
            for table in ("notes", "operations", "approvals", "audit_events"):
                assert db.execute(f"select count(*) from {table}").fetchone() == (0,)


def test_reservation_excludes_competitors_and_replacement(tmp_path: Path) -> None:
    from mcp_agent_server.agent.recording import replay, reserve

    record = replay(Path("examples/search-read.json"))
    dest = tmp_path / "capture"
    with reserve(dest) as finish:
        with pytest.raises(FileExistsError), reserve(dest):
            pytest.fail("second writer admitted")
        with pytest.raises(BlockingIOError):
            replay(dest)
        dest.unlink()
        dest.write_text("replacement")
        with pytest.raises(ValueError, match="destination changed"):
            finish(record)
    assert dest.read_text() == "replacement"
    link = tmp_path / "link"
    link.symlink_to(dest)
    with pytest.raises(OSError), reserve(link):
        pytest.fail("symlink admitted")
    parent = tmp_path / "redirect"
    parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError), reserve(parent / "other"):
        pytest.fail("parent symlink admitted")
    assert not (tmp_path / "other").exists()


def test_reserved_cli_success(tmp_path: Path, audit_db: Path) -> None:
    from mcp_agent_server.agent.recording import replay

    path = tmp_path / "note.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_agent_server.agent",
            "run",
            "--scenario",
            "note",
            "--allow-write",
            "write_note",
            "--record",
            str(path),
        ],
        env={**os.environ, "MCP_AGENT_AUDIT_DB": str(audit_db)},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0 and path.stat().st_mode & 0o777 == 0o600
    assert replay(path).model_dump(mode="json") == json.loads(proc.stdout)["recording"]
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("select count(*) from notes").fetchone() == (1,)
