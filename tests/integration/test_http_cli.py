import asyncio
import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from security.test_http_security import body, headers

from mcp_agent_server.config import PROJECT
from mcp_agent_server.tools.registry import SPECS

from .http_support import client


def environment(path: Path, port: int) -> dict[str, str]:
    return {
        "MCP_AGENT_HTTP_ENABLED": "true",
        "MCP_AGENT_HTTP_PORT": str(port),
        "MCP_AGENT_AUDIT_DB": str(path),
        **(
            {"COVERAGE_PROCESS_CONFIG": os.environ["COVERAGE_PROCESS_CONFIG"]}
            if "COVERAGE_PROCESS_CONFIG" in os.environ
            else {}
        ),
    }


@pytest.mark.asyncio
async def test_http_cli_private_credential_logs_and_shutdown(audit_db: Path) -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    directory = PROJECT / ".runtime/http"
    before = set(directory.glob("client-*.json"))
    logs, stdout = audit_db.parent / "http.stderr", audit_db.parent / "http.stdout"
    with logs.open("w") as err, stdout.open("w") as out:
        process = subprocess.Popen(
            [sys.executable, "-m", "mcp_agent_server"],
            env=environment(audit_db, port),
            stdout=out,
            stderr=err,
        )
        try:
            async with asyncio.timeout(8):
                while not (files := set(directory.glob("client-*.json")) - before):
                    assert process.poll() is None
                    await asyncio.sleep(0.01)
                credential = next(iter(files))
                assert stat.S_IMODE(credential.stat().st_mode) == 0o600
                # A file may exist before its short write has completed.
                while True:
                    try:
                        values = json.loads(credential.read_text())
                        break
                    except json.JSONDecodeError:
                        await asyncio.sleep(0.01)
                token = SecretStr(values["token"])
                url = f"http://127.0.0.1:{port}/mcp"
                async with httpx.AsyncClient(trust_env=False) as raw:
                    while True:
                        try:
                            r = await raw.post(
                                url, headers=headers(token.get_secret_value()), json=body()
                            )
                            assert r.status_code == 200
                            break
                        except httpx.ConnectError:
                            await asyncio.sleep(0.02)
                    denied = await raw.post(
                        url,
                        headers={**headers(token.get_secret_value()), "host": "evil.example"},
                        json=body(),
                    )
                    assert denied.status_code == 421
                async with client(url, token) as c:
                    assert {t.name for t in (await c.list_tools()).tools} == set(SPECS)
                    from mcp import MCPError

                    with pytest.raises(MCPError):
                        await c.call_tool("health", {"private": "SYNTHETIC_PRIVATE_ARGUMENT"})
        finally:
            process.terminate()
            await asyncio.to_thread(process.wait, 8)
    assert process.returncode == -15  # Uvicorn re-raises SIGTERM after graceful lifespan shutdown.
    assert not credential.exists()
    assert stdout.read_text() == ""
    text = logs.read_text()
    records = [json.loads(line) for line in text.splitlines()]
    assert records and all("message" in r for r in records)
    assert "SYNTHETIC_PRIVATE_ARGUMENT" not in text and token.get_secret_value() not in text
    assert "evil.example" not in text
    assert "Traceback" not in text and "--- Logging error ---" not in text
    assert any(r.get("context", {}).get("error_code") == "invalid_tool_arguments" for r in records)
    print(
        "HTTP CLI endpoint",
        url,
        "credential_mode=0600 stderr=JSON stdout_empty=True shutdown_signal=SIGTERM cleanup=True",
    )


@pytest.mark.parametrize("failure", ["bind", "occupied"])
def test_http_startup_failure(audit_db: Path, failure: str) -> None:
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        env = environment(audit_db, occupied.getsockname()[1])
        if failure == "bind":
            env["MCP_AGENT_HTTP_HOST"] = "0.0.0.0"
        before = set((PROJECT / ".runtime/http").glob("client-*.json"))
        result = subprocess.run(
            [sys.executable, "-m", "mcp_agent_server"],
            env=env,
            capture_output=True,
            text=True,
            timeout=8,
        )
    assert result.returncode == (2 if failure == "bind" else 3)
    assert not result.stdout and result.stderr
    assert all(json.loads(line) for line in result.stderr.splitlines())
    assert "Traceback" not in result.stderr and "--- Logging error ---" not in result.stderr
    assert set((PROJECT / ".runtime/http").glob("client-*.json")) == before
    print("HTTP startup", failure, "exit", result.returncode, "JSON=True credentials_cleaned=True")
