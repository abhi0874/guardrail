"""Level cancellation must retain one durable interrupted post-event."""

import time
from pathlib import Path
from uuid import uuid4

import anyio
import pytest
from pydantic import BaseModel

from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails.models import GuardrailRequest
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.guardrails.validation import HealthArguments


@pytest.mark.asyncio
@pytest.mark.parametrize("post_delay", [0, 0.02])
async def test_level_cancellation_retains_durable_post_event(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch, post_delay: float
) -> None:
    store = AuditStore(audit_db)
    append = store.append

    def delayed(event: AuditEvent) -> None:
        if event.phase == "post":
            time.sleep(post_delay)
        append(event)

    monkeypatch.setattr(store, "append", delayed)
    pipeline = Pipeline(store, {"health": HealthArguments}, 100, 2)
    with anyio.CancelScope() as scope:

        async def handler(_: BaseModel) -> str:
            pipeline.claim("health")
            scope.cancel()
            await anyio.sleep(0)
            raise AssertionError("Cancelled handler must not return")

        await pipeline.execute(
            GuardrailRequest(connection_id=uuid4(), tool_name="health", arguments={}), handler
        )
    assert scope.cancelled_caught
    with store.transaction() as db:
        assert db.execute("select phase,status from audit_events order by rowid").fetchall() == [
            ("pre", "not_executed"),
            ("post", "interrupted"),
        ]
