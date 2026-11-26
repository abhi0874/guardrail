import asyncio
import json
import os
import sys
from importlib.metadata import version
from pathlib import Path

import pytest
from mcp import MCPError

from .audit_support import connected, rows


@pytest.mark.asyncio
async def test_protocol_persistent_restart_and_correlation(audit_db: Path) -> None:
    for _ in range(2):
        async with connected(audit_db) as client:
            assert client.protocol_version == "2026-07-28"
            assert sorted(t.name for t in (await client.list_tools()).tools) == [
                "fetch_url",
                "health",
                "read_document",
                "search_documents",
                "send_message",
                "write_note",
            ]
            result = await client.call_tool("health")
            assert not result.is_error and result.structured_content == {
                "service": "mcp-agent-server",
                "status": "ok",
                "version": version("mcp-agent-server"),
            }
    events = rows(audit_db)
    assert [r["phase"] for r in events] == ["pre", "post", "pre", "post"]
    assert [r["status"] for r in events] == ["not_executed", "succeeded"] * 2
    assert len({r["event_id"] for r in events}) == 4
    assert len({r["connection_id"] for r in events}) == 2
    assert events[0]["request_id"] == events[1]["request_id"] != events[2]["request_id"]
    print("two real stdio processes, four durable events, two request IDs")


@pytest.mark.asyncio
async def test_real_denials_and_connection_recovery(audit_db: Path) -> None:
    secret = "PRIVATE_TEST_VALUE"
    async with connected(
        audit_db, limits={"MCP_AGENT_MAX_ARGUMENT_BYTES": "64", "MCP_AGENT_MAX_ARGUMENT_DEPTH": "2"}
    ) as client:
        cases: list[tuple[str, dict[str, object], str]] = [
            ("health", {"token": secret}, "invalid_tool_arguments"),
            ("health", {"nested": [{}]}, "invalid_tool_arguments"),
            ("health", {"payload": "X" * 100}, "request_too_large"),
            ("unknown-" + secret, {}, "unknown_tool"),
        ]
        for name, args, code in cases:
            with pytest.raises(MCPError) as failure:
                await client.call_tool(name, args)
            assert failure.value.data["code"] == code
            row = rows(audit_db)[-1]
            assert row["phase"] == "denied" and row["allowed"] == 0
            assert row["request_id"] == failure.value.data["request_id"]
            assert row["error_code"] == code and secret not in str(failure.value.data)
        assert not (await client.call_tool("health")).is_error
        assert not (await client.call_tool("health", {})).is_error
    events = rows(audit_db)
    assert [r["phase"] for r in events] == ["denied"] * 4 + ["pre", "post", "pre", "post"]
    assert events[-4]["connection_id"] == events[-1]["connection_id"]
    assert events[-4]["request_id"] != events[-1]["request_id"]
    assert secret.encode() not in audit_db.read_bytes()
    stderr = (audit_db.parent / "stderr.jsonl").read_text()
    assert secret not in stderr
    assert all(isinstance(json.loads(line), dict) for line in stderr.splitlines())


@pytest.mark.asyncio
async def test_malformed_transport_input_has_no_invented_events(audit_db: Path) -> None:
    async with asyncio.timeout(10):
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_agent_server",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"MCP_AGENT_AUDIT_DB": str(audit_db), "PATH": os.defpath},
            cwd=audit_db.parent,
        )
        try:
            await process.communicate(b"not-a-json-rpc-frame\n")
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
    assert process.returncode == 0
    assert rows(audit_db) == []
