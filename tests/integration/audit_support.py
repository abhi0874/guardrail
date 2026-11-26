import asyncio
import os
import sqlite3
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, closing
from pathlib import Path

from mcp import Client, StdioServerParameters, stdio_client


@asynccontextmanager
async def connected(
    db: Path, *, bootstrap: str | None = None, limits: dict[str, str] | None = None
) -> AsyncIterator[Client]:
    env = {"MCP_AGENT_AUDIT_DB": str(db), **(limits or {})}
    if coverage := os.environ.get("COVERAGE_PROCESS_CONFIG"):
        env["COVERAGE_PROCESS_CONFIG"] = coverage
    args = ["-c", bootstrap] if bootstrap else ["-m", "mcp_agent_server"]
    params = StdioServerParameters(command=sys.executable, args=args, env=env, cwd=db.parent)
    async with asyncio.timeout(15):
        with (db.parent / "stderr.jsonl").open("a") as log:
            async with Client(stdio_client(params, errlog=log), read_timeout_seconds=5) as client:
                yield client


def rows(db: Path) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        return list(conn.execute("SELECT * FROM audit_events ORDER BY rowid"))
