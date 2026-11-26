import asyncio
from pathlib import Path

import pytest
from mcp import MCPError

from mcp_agent_server.audit.storage import AuditStore

from .http_support import client, listener
from .test_production_tools import key


@pytest.mark.asyncio
async def test_concurrent_contexts_never_share_receipts(audit_db: Path) -> None:
    async with listener(audit_db) as (url, clients, _):
        a, ar = clients.issue()
        b, br = clients.issue()
        async with client(url, a) as ca, client(url, b) as cb:
            from mcp import Client

            async def write(who: Client, prefix: str) -> None:
                for i in range(5):
                    op = f"{prefix}-{i}"
                    value = {"title": op, "body": "Synthetic"}
                    r = await who.call_tool("write_note", value, meta=key(op))
                    again = await who.call_tool("write_note", value, meta=key(op))
                    assert r.structured_content == again.structured_content

            await asyncio.gather(write(ca, "a"), write(cb, "b"))
            for who, other in [(ca, "b"), (cb, "a")]:
                for i in range(5):
                    op = f"{other}-{i}"
                    with pytest.raises(MCPError) as err:
                        await who.call_tool(
                            "write_note", {"title": op, "body": "Synthetic"}, meta=key(op)
                        )
                    assert err.value.data["code"] == "idempotency_key_conflict"
        with AuditStore(audit_db).transaction() as db:
            assert db.execute("SELECT count(*) FROM notes").fetchone() == (10,)
            for prefix, ref in [("a", ar), ("b", br)]:
                # Note IDs are only returned to the capability that created them.
                rows = db.execute(
                    "SELECT n.title,o.connection FROM operations o JOIN notes n "
                    "ON json_extract(o.receipt,'$.note_id')=n.note_id "
                    "WHERE n.title LIKE ?",
                    (prefix + "-%",),
                ).fetchall()
                assert len(rows) == 5 and all(r[1] == str(ref.identifier) for r in rows)
        print("HTTP concurrency: clients=2 notes=10 same-client_replays=10 cross-client_denials=10")
