from pathlib import Path

import pytest
from mcp import MCPError

from .audit_support import connected, rows

# Only the test process supplies a marker-writing health implementation. Its registration,
# middleware, validated dispatch, stdio transport and SQLite store are the production ones.
BOOTSTRAP = """
import logging
from importlib.metadata import version
from mcp_agent_server.config import Settings
from mcp_agent_server.logging import configure_logging
from mcp_agent_server.server import Health, create_server
s=Settings.from_env()
logger=configure_logging(s.log_level)
logging.basicConfig(level=s.log_level,handlers=logger.handlers)
def probe():
    (s.audit_db.parent/'handler-ran').touch()
    if (s.audit_db.parent/'break-post').exists():
        s.audit_db.rename(s.audit_db.with_suffix('.saved'))
    if (s.audit_db.parent/'throw').exists():
        raise RuntimeError('/private/INTERNAL_TEST_SECRET')
    return Health(service=s.app_name,version=version('guardrail-mcp-server'))
server=create_server(s,health_handler=probe)
server.run(transport='stdio')
"""


@pytest.mark.asyncio
async def test_pre_audit_and_validation_deny_before_handler(audit_db: Path) -> None:
    marker = audit_db.parent / "handler-ran"
    async with connected(audit_db, bootstrap=BOOTSTRAP) as client:
        await client.list_tools()
        with pytest.raises(MCPError) as invalid:
            await client.call_tool("health", {"unexpected": "value"})
        assert invalid.value.data["code"] == "invalid_tool_arguments" and not marker.exists()
        saved = audit_db.with_suffix(".saved")
        audit_db.rename(saved)
        with pytest.raises(MCPError) as failure:
            await client.call_tool("health")
        assert failure.value.data["code"] == "audit_unavailable" and not marker.exists()
        assert not audit_db.exists()
        assert [r["phase"] for r in rows(saved)] == ["denied"]
        saved.rename(audit_db)
        assert not (await client.call_tool("health")).is_error and marker.exists()
    print("pre-audit unavailable: marker absent; restored store: handler ran")


@pytest.mark.asyncio
async def test_post_failure_withholds_success(audit_db: Path) -> None:
    (audit_db.parent / "break-post").touch()
    async with connected(audit_db, bootstrap=BOOTSTRAP) as client:
        await client.list_tools()
        with pytest.raises(MCPError) as failure:
            await client.call_tool("health")
        assert failure.value.data["code"] == "audit_integrity_failure"
    assert (audit_db.parent / "handler-ran").is_file()
    assert [r["phase"] for r in rows(audit_db.with_suffix(".saved"))] == ["pre"]
    print("post-audit unavailable: marker present, durable pre only, client received error")


@pytest.mark.asyncio
async def test_tool_exception_has_safe_wire_error(audit_db: Path) -> None:
    (audit_db.parent / "throw").touch()
    async with connected(audit_db, bootstrap=BOOTSTRAP) as client:
        with pytest.raises(MCPError) as failure:
            await client.call_tool("health")
    assert failure.value.data["code"] == "tool_execution_failed"
    assert "/private/" not in str(failure.value.data)
    assert "INTERNAL_TEST_SECRET" not in (audit_db.parent / "stderr.jsonl").read_text()
    assert rows(audit_db)[-1]["status"] == "dispatch_failed"


@pytest.mark.asyncio
async def test_sdk_registration_alone_cannot_grant_permission(audit_db: Path) -> None:
    extra = BOOTSTRAP.replace(
        "server.run(transport='stdio')",
        """
@server.tool()
async def surprise() -> str:
    (s.audit_db.parent/'unapproved-handler').touch()
    return 'unexpected'
server.run(transport='stdio')
""",
    )
    async with connected(audit_db, bootstrap=extra) as client:
        assert "surprise" in [tool.name for tool in (await client.list_tools()).tools]
        with pytest.raises(MCPError) as failure:
            await client.call_tool("surprise")
    assert failure.value.data["code"] == "unknown_tool"
    assert not (audit_db.parent / "unapproved-handler").exists()
    assert rows(audit_db)[-1]["phase"] == "denied"


@pytest.mark.asyncio
async def test_invalid_startup_schema_returns_safe_diagnostic(audit_db: Path) -> None:
    import asyncio
    import json
    import sqlite3
    import sys
    from contextlib import closing

    with closing(sqlite3.connect(audit_db)) as db:
        db.execute("PRAGMA user_version=99")
    async with asyncio.timeout(10):
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_agent_server",
            env={"MCP_AGENT_AUDIT_DB": str(audit_db)},
            cwd=audit_db.parent,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await child.communicate()
    assert child.returncode == 1 and not out
    assert json.loads(err)["context"]["error_code"] == "audit_unavailable"
    assert str(audit_db).encode() not in err and b"Traceback" not in err
