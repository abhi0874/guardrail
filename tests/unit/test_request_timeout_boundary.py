"""An unmodified SDK timeout may precede entry to a dependency handler."""

import asyncio
import sqlite3
from contextlib import closing
from pathlib import Path

import httpx
import pytest
from integration.http_support import client, listener
from mcp import MCPError
from mcp_types import REQUEST_TIMEOUT

from mcp_agent_server.adapters.http import Fetcher


@pytest.mark.asyncio
async def test_real_sdk_timeout_before_fetch_entry(audit_db: Path) -> None:
    resolving, cancelled = asyncio.Event(), asyncio.Event()
    entries = 0

    async def resolve(host: str) -> list[str]:
        resolving.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        raise AssertionError("Resolver must be cancelled")

    async def respond(request: httpx.Request) -> httpx.Response:
        nonlocal entries
        entries += 1
        raise AssertionError("The dependency must never be entered")

    fetcher = Fetcher(
        ("docs.example.org",), resolver=resolve, transport=lambda: httpx.MockTransport(respond)
    )
    async with asyncio.timeout(5):
        async with listener(audit_db, fetcher=fetcher, fetch_hosts=["docs.example.org"]) as (
            url,
            registry,
            _,
        ):
            secret, _ = registry.issue()
            async with client(url, secret) as peer:
                await peer.list_tools()
                with pytest.raises(MCPError) as error:
                    await peer.call_tool(
                        "fetch_url", {"url": "https://docs.example.org/a"}, read_timeout_seconds=0.1
                    )
                assert error.value.code == REQUEST_TIMEOUT
                await cancelled.wait()
    assert resolving.is_set() and entries == 0 and cancelled.is_set()
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == 0
        assert (
            db.execute("SELECT count(*) FROM audit_events WHERE phase='pre'").fetchone()[0]
            == db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone()[0]
        )
