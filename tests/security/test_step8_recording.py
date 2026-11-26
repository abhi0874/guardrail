import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_agent_server.agent.connection import read_token
from mcp_agent_server.agent.recording import Recording, replay, save


def test_passive_playback_and_schema(tmp_path: Path) -> None:
    sample = Path("examples/search-read.json")
    original = replay(sample)
    path = tmp_path / "safe.json"
    save(path, original)
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        save(path, original)
    assert replay(path) == original
    # Trap all socket operations, subprocess launches, and imports of live client components.
    code = """
import sys,runpy
def guard(event,args):
    if event.startswith('socket.') or event=='subprocess.Popen':
        raise AssertionError(event)
    if event=='import' and args[0] in {
        'mcp','httpx','httpx2','mcp_agent_server.agent.runner',
        'mcp_agent_server.agent.ollama','mcp_agent_server.agent.fake'}:
        raise AssertionError(args[0])
sys.addaudithook(guard)
sys.argv=['agent','replay',sys.argv[1]]
runpy.run_module('mcp_agent_server.agent',run_name='__main__')
"""
    p = subprocess.run(
        [sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=5
    )
    assert p.returncode == 0 and not p.stderr
    assert Recording.model_validate_json(p.stdout) == original
    changes: list[dict[str, object]] = [
        {"version": 2},
        {"answer": "private-secret"},
        {"tokens": ["secret"]},
        {"events": [{}] * 33},
    ]
    for change in changes:
        path.write_text(json.dumps({**original.model_dump(mode="json"), **change}))
        with pytest.raises(ValueError, match="Invalid recording"):
            replay(path)
    path.write_bytes(b"x" * 32769)
    with pytest.raises(ValueError, match="too large"):
        replay(path)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        replay(link)


def test_capability_input_privacy(tmp_path: Path) -> None:
    p = tmp_path / "credential"
    p.write_text('{"token":"private"}')
    p.chmod(0o644)
    with pytest.raises(ValueError, match="Private capability"):
        read_token(p)
    p.chmod(0o600)
    with pytest.raises(ValueError, match="Invalid capability"):
        read_token(p)
