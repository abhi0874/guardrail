"""Actual Docker/official-MCP smoke checks. No public listener or credentials."""

import argparse
import asyncio
import json
import subprocess
import tempfile
import time
from uuid import uuid4

from mcp import Client, StdioServerParameters, stdio_client

from mcp_agent_server.agent.fake import FakeLLM, scenario
from mcp_agent_server.agent.runner import run

TOOLS = {"health", "search_documents", "read_document", "write_note", "send_message", "fetch_url"}


def docker(*args: str) -> str:
    return subprocess.check_output(
        ["docker", *args], text=True, stderr=subprocess.STDOUT, timeout=60
    )


async def smoke(image: str) -> None:
    prefix = "mcp-smoke-" + uuid4().hex[:12]
    volume, http = prefix + "-data", prefix + "-http"
    common = [
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--pids-limit",
        "128",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--mount",
        f"type=volume,src={volume},dst=/app/.runtime",
    ]
    docker("volume", "create", volume)
    try:
        for trial in (1, 2):
            params = StdioServerParameters(
                command="docker",
                args=["run", "--rm", "-i", "--name", prefix, *common, image],
            )
            with tempfile.TemporaryFile(mode="w+") as log:
                async with asyncio.timeout(30):
                    async with Client(stdio_client(params, errlog=log)) as client:
                        assert {t.name for t in (await client.list_tools()).tools} == TOOLS
                        assert (await client.call_tool("health", {})).structured_content == {
                            "status": "ok",
                            "service": "mcp-agent-server",
                            "version": "0.1.0",
                        }
                        if trial == 1:
                            note = json.dumps(
                                {
                                    "calls": [
                                        {
                                            "name": "write_note",
                                            "arguments": {
                                                "title": "Container synthetic",
                                                "body": "One durable local effect.",
                                            },
                                        }
                                    ]
                                }
                            )
                            r = await run(
                                client,
                                FakeLLM([note, note, '{"content":"Done"}']),
                                "Synthetic smoke.",
                                allow_writes=frozenset({"write_note"}),
                            )
                            assert r.recording.reason == "complete"
                            assert [e.replayed for e in r.recording.events] == [False, True]
                            r = await run(
                                client,
                                scenario("message"),
                                "Synthetic smoke.",
                                allow_writes=frozenset({"send_message"}),
                            )
                            assert r.recording.events[-1].code == "approval_required"
                log.seek(0)
                assert "--- Logging error ---" not in log.read()
        query = """import json,sqlite3
from contextlib import closing
with closing(sqlite3.connect('file:/app/.runtime/audit/events.sqlite3?mode=ro',uri=True)) as d:
 n=d.execute('select count(*) from notes').fetchone()[0]
 o=d.execute('select count(*) from operations').fetchone()[0]
 a=d.execute('select count(*) from approvals where consumed_at is not null').fetchone()[0]
 assert (n,o,a)==(1,1,0)
 print(json.dumps(dict(notes=n,operations=o,consumed_approvals=a)))
"""
        persisted = json.loads(
            docker("run", "--rm", *common, "--entrypoint", "python", image, "-c", query)
        )
        inventory = """import importlib.metadata,json,os
from pathlib import Path
assert os.geteuid()==10001
names={d.metadata['Name'].lower() for d in importlib.metadata.distributions()}
assert 'google-genai' not in names and 'agent-security-scanner' not in names
assert not Path('/app/security-tests').exists() and not Path('/app/.cache').exists()
assert not list(Path('/app/src').rglob('*.pyc'))
assert not list(Path('/app').glob('.env*'))
print(json.dumps(dict(uid=os.geteuid(),optional_providers_installed=False,scanner_installed=False)))
"""
        nonroot = json.loads(
            docker("run", "--rm", *common, "--entrypoint", "python", image, "-c", inventory)
        )
        demo = docker(
            "run",
            "--rm",
            *common,
            "--entrypoint",
            "python",
            image,
            "-m",
            "mcp_agent_server.agent",
            "demo",
        )
        assert "Replay mutations: 0" in demo and "Six production tools:" in demo
        docker("run", "-d", "--name", http, *common, "-e", "MCP_AGENT_HTTP_ENABLED=true", image)
        check = """import asyncio
from pathlib import Path
from mcp_agent_server.agent.connection import connect
async def main():
 files=list(Path('.runtime/http').glob('*.json'))
 assert len(files)==1
 async with connect(credential=files[0]) as c:
  assert (await c.call_tool('health',{})).structured_content['status']=='ok'
asyncio.run(main())
"""
        for _ in range(30):
            try:
                docker("exec", http, "python", "-c", check)
                break
            except subprocess.CalledProcessError:
                await asyncio.sleep(0.1)
        else:
            raise AssertionError("Authenticated container loopback HTTP unavailable")
        start = time.monotonic()
        docker("stop", "--timeout", "10", http)
        stopped = time.monotonic() - start
        assert stopped < 10
        state = json.loads(docker("inspect", http))[0]
        assert not state["State"]["Running"] and state["State"]["ExitCode"] in (0, 143)
        assert state["HostConfig"]["PortBindings"] == {}
        docker(
            "run",
            "--rm",
            *common,
            "--entrypoint",
            "python",
            image,
            "-c",
            "from pathlib import Path; assert not list(Path('/app/.runtime/http').glob('*.json'))",
        )
        logs = docker("logs", http)
        assert "--- Logging error ---" not in logs
        print(
            json.dumps(
                dict(
                    image=image,
                    tools=sorted(TOOLS),
                    persistence=persisted,
                    runtime=nonroot,
                    graceful_http_stop_seconds=stopped,
                    no_published_ports=True,
                    real_stdio=True,
                    authenticated_container_loopback=True,
                    offline_demo=True,
                ),
                sort_keys=True,
            )
        )
    finally:
        subprocess.run(["docker", "rm", "-f", prefix, http], capture_output=True, check=False)
        docker("volume", "rm", volume)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="mcp-agent-server:local")
    args = parser.parse_args()
    asyncio.run(smoke(args.image))
