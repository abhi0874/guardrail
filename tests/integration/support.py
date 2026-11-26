"""Exercise the installed executable through the official SDK's subprocess transport."""

import asyncio
import json
import os
import sys
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from mcp import Client, StdioServerParameters, stdio_client
from mcp.client.session import IncomingMessage

from mcp_agent_server.config import AUDIT_ROOT


async def check_stdio(args: list[str], directory: Path) -> None:
    AUDIT_ROOT.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=AUDIT_ROOT) as temporary:
        await _probe(args, directory, Path(temporary) / "test.sqlite3")


async def _probe(args: list[str], directory: Path, db: Path) -> None:
    parse_errors: list[Exception] = []

    async def on_message(message: IncomingMessage) -> None:
        if isinstance(message, Exception):
            parse_errors.append(message)

    # The SDK filters the parent environment. Forward only test coverage configuration.
    coverage_config = os.environ.get("COVERAGE_PROCESS_CONFIG")
    params = StdioServerParameters(
        command=sys.executable,
        args=args,
        cwd=directory,
        env={
            "MCP_AGENT_AUDIT_DB": str(db),
            **({"COVERAGE_PROCESS_CONFIG": coverage_config} if coverage_config else {}),
        },
    )
    diagnostics = directory / "server.stderr"
    async with asyncio.timeout(15):
        with diagnostics.open("w", encoding="utf-8") as errlog:
            async with Client(
                stdio_client(params, errlog=errlog),
                message_handler=on_message,
                read_timeout_seconds=5,
            ) as client:
                protocol = client.protocol_version
                assert protocol == "2026-07-28"
                assert client.server_info is not None
                assert client.server_info.version == version("mcp-agent-server")
                listing = await client.list_tools()
                assert sorted(tool.name for tool in listing.tools) == [
                    "fetch_url",
                    "health",
                    "read_document",
                    "search_documents",
                    "send_message",
                    "write_note",
                ]
                tool = next(t for t in listing.tools if t.name == "health")
                assert tool.input_schema.get("properties") == {}
                assert tool.output_schema is not None
                first = await client.call_tool("health", {})
                second = await client.call_tool("health")
                expected = {
                    "status": "ok",
                    "service": "mcp-agent-server",
                    "version": version("mcp-agent-server"),
                }
                assert not first.is_error and not second.is_error
                assert first.structured_content == second.structured_content == expected
                print(
                    f"protocol={protocol} tools={[t.name for t in listing.tools]} "
                    f"structured={json.dumps(expected)}"
                )
    assert not parse_errors, "Unexpected non-protocol output or transport error"
    records = [json.loads(line) for line in diagnostics.read_text().splitlines()]
    startup = next(record for record in records if record["message"] == "Starting MCP server")
    pid = startup["context"]["process_id"]
    assert startup["context"]["transport"] == "stdio"
    if os.name == "posix":
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    print("stderr=JSON stdout_parse_errors=0 subprocess_closed=true")
