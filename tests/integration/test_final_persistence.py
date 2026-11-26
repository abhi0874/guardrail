"""Cancellation barriers inspect real durable state after caller termination."""

import asyncio
import threading
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import BaseModel

from mcp_agent_server.audit.lifecycle import Persistence
from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.models import GuardrailRequest
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.guardrails.validation import HealthArguments

from .mutation_fixture import Fixture


class Gate:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def block(self) -> None:
        self.entered.set()
        assert self.release.wait(5), "Test controller must release its worker"

    async def wait(self) -> None:
        assert await asyncio.to_thread(self.entered.wait, 2)

    async def cancel(self, task: asyncio.Task[object], count: int = 1) -> None:
        # FIFO loop callback is a scheduling barrier after each cancellation delivery.
        for _ in range(count):
            acknowledged = asyncio.Event()
            task.cancel()
            asyncio.get_running_loop().call_soon(acknowledged.set)
            await acknowledged.wait()
            assert not task.done()


@pytest.mark.asyncio
@pytest.mark.parametrize("point", ["pre", "effect", "before_post", "post", "committed"])
@pytest.mark.parametrize("repeated", [False, True])
async def test_direct_cancellation_settles_audit(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch, point: str, repeated: bool
) -> None:
    store = AuditStore(audit_db)
    pipe = Pipeline(store, {"health": HealthArguments}, 100, 2)
    gate = Gate()
    append = store.append
    effects = 0

    def blocked(event: AuditEvent) -> None:
        if event.phase == point or (event.phase == "post" and point == "before_post"):
            gate.block()
        append(event)
        if event.phase == "post" and point == "committed":
            gate.block()

    monkeypatch.setattr(store, "append", blocked)
    effect_started = asyncio.Event()

    async def handler(_: BaseModel) -> str:
        nonlocal effects
        pipe.claim("health")
        effects += 1
        if point == "effect":
            effect_started.set()
            await asyncio.Event().wait()
        if point == "before_post":
            asyncio.get_running_loop().call_soon(task.cancel)
        return "ok"

    task = asyncio.create_task(
        pipe.execute(
            GuardrailRequest(connection_id=uuid4(), tool_name="health", arguments={}), handler
        )
    )
    try:
        if point == "effect":
            await effect_started.wait()

            # Place a real barrier on its interrupted post-event.
            def blocked_post(event: AuditEvent) -> None:
                if event.phase == "post":
                    gate.block()
                append(event)

            monkeypatch.setattr(store, "append", blocked_post)
            task.cancel()
        await gate.wait()
        await gate.cancel(task, 4 if repeated else 1)
    finally:
        gate.release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await pipe.persistence.aclose()
    assert pipe.persistence.pending == 0
    # A newly opened store observes committed state (not a writer's private view).
    with AuditStore(audit_db).transaction() as db:
        rows = db.execute(
            "select phase,status,parent_event_id from audit_events order by rowid"
        ).fetchall()
        pre = db.execute("select event_id from audit_events where phase='pre'").fetchone()[0]
        if point == "pre":
            assert effects == 0 and len(rows) == 1
        else:
            assert effects == 1 and len(rows) == 2 and rows[1][2] == pre
            assert rows[1][1] == ("interrupted" if point == "effect" else "succeeded")


@pytest.mark.asyncio
async def test_commit_failure_wins_over_cancellation(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AuditStore(audit_db)
    pipe = Pipeline(store, {"health": HealthArguments}, 100, 2)
    gate = Gate()
    append = store.append

    def failed(event: AuditEvent) -> None:
        if event.phase == "post":
            gate.block()
            raise OSError("private storage detail")
        append(event)

    monkeypatch.setattr(store, "append", failed)

    async def handler(_: BaseModel) -> str:
        pipe.claim("health")
        return "ok"

    task = asyncio.create_task(
        pipe.execute(
            GuardrailRequest(connection_id=uuid4(), tool_name="health", arguments={}), handler
        )
    )
    try:
        await gate.wait()
        await gate.cancel(task, 3)
    finally:
        gate.release.set()
    execution, value = await task
    assert value is None and execution.error and execution.error.code is ErrorCode.AUDIT_INTEGRITY
    assert "private" not in execution.error.message
    assert pipe.persistence.pending == 0


@pytest.mark.asyncio
async def test_deadline_is_unknown_fenced_and_supervised(audit_db: Path) -> None:
    store = AuditStore(audit_db)
    persistence = Persistence(0.1)
    gate = Gate()

    def late_transaction() -> None:
        with store.transaction() as db:
            db.execute("PRAGMA application_id=123")
            gate.block()  # expire after SQL but before COMMIT

    task = asyncio.create_task(persistence.run(late_transaction))
    try:
        await gate.wait()
        with pytest.raises(GuardrailError) as caught:
            await task
        assert caught.value.public.code is ErrorCode.AUDIT_INTEGRITY
        assert persistence.pending == 1
        with pytest.raises(GuardrailError):
            await persistence.run(lambda: None)  # fail closed while expired work is owned
    finally:
        gate.release.set()
    await persistence.aclose()
    assert persistence.pending == 0
    with store.transaction() as db:
        assert db.execute("PRAGMA application_id").fetchone()[0] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("point", ["admit", "local_effect", "finish", "interrupt"])
async def test_mutation_cancellation_retains_state_and_single_approval(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    fixture = Fixture(audit_db, uuid4())
    fixture.approve()
    service = fixture.pipe.mutation_service
    assert service
    gate = Gate()
    original: Callable[..., object] = getattr(service.store, point)

    def blocked(*args: object) -> object:
        gate.block()
        return original(*args)

    monkeypatch.setattr(service.store, point, blocked)
    task = asyncio.create_task(fixture.call())
    if point == "interrupt":
        # Force a cancellable handler so the cleanup path reaches its barrier.
        started = asyncio.Event()

        async def stop(_: BaseModel) -> dict[str, object]:
            fixture.pipe.claim("increment")
            started.set()
            await asyncio.Event().wait()
            raise AssertionError

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        task = asyncio.create_task(
            fixture.pipe.execute(fixture.request(), stop, idempotency_key="sample-key")
        )
        await started.wait()
        task.cancel()
    try:
        await gate.wait()
        await gate.cancel(task, 4)
    finally:
        gate.release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await fixture.pipe.persistence.aclose()
    assert fixture.pipe.persistence.pending == 0
    with fixture.store.transaction() as db:
        assert db.execute("select count(*) from operations").fetchone()[0] == 1
        assert db.execute("select count(consumed_event) from approvals").fetchone()[0] == 1
        state = db.execute("select state from operations").fetchone()[0]
        assert state == {"admit": "FAILED_BEFORE_EFFECT", "finish": "COMPLETED"}.get(
            point, "OUTCOME_UNKNOWN"
        )
        assert db.execute("select count(*) from audit_events where phase='post'").fetchone()[0] == 1
    assert fixture.count() == (1 if point in ("local_effect", "finish") else 0)


@pytest.mark.asyncio
async def test_shutdown_drains_owned_worker(audit_db: Path) -> None:
    persistence = Persistence()
    gate = Gate()
    store = AuditStore(audit_db)

    def operation() -> None:
        gate.block()
        with store.transaction() as db:
            db.execute("PRAGMA application_id=42")

    task = asyncio.create_task(persistence.run(operation))
    await gate.wait()
    closing = asyncio.create_task(persistence.aclose())
    ready = asyncio.Event()
    asyncio.get_running_loop().call_soon(ready.set)
    await ready.wait()
    try:
        await gate.cancel(closing, 3)
        assert persistence.pending == 1
    finally:
        gate.release.set()
    await task
    with pytest.raises(asyncio.CancelledError):
        await closing
    assert persistence.pending == 0
    with store.transaction() as db:
        assert db.execute("PRAGMA application_id").fetchone()[0] == 42


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["write_note", "send_message"])
async def test_real_http_lost_reply_does_not_duplicate_effects(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    import sqlite3
    from typing import Any

    from mcp_agent_server.adapters.outbox import Outbox
    from mcp_agent_server.guardrails.approval import ApprovalGate
    from mcp_agent_server.guardrails.policy import load_policy
    from mcp_agent_server.tools.models import Message

    from .http_support import client, listener
    from .test_production_tools import key

    pipes = []

    def factory(*args: Any, **kwargs: Any) -> Pipeline:
        pipe = Pipeline(*args, **kwargs)
        pipes.append(pipe)
        return pipe

    monkeypatch.setattr("mcp_agent_server.server.Pipeline", factory)
    outbox = Outbox()
    gate = Gate()
    completed = asyncio.Event()
    loop = asyncio.get_running_loop()
    async with listener(audit_db, outbox=outbox) as (url, registry, _):
        token, ref = registry.issue()
        pipe = pipes[0]
        assert pipe.mutation_service
        original = pipe.mutation_service.store.finish

        def finish(operation: str, event: AuditEvent) -> None:
            gate.block()
            original(operation, event)
            loop.call_soon_threadsafe(completed.set)

        monkeypatch.setattr(pipe.mutation_service.store, "finish", finish)
        args = {"title": "Synthetic", "body": "One note."}
        if tool == "send_message":
            message = Message(recipient="ops-lab", subject="Synthetic", body="One append.")
            args = message.model_dump()
            ApprovalGate(AuditStore(audit_db), load_policy()).issue(
                ref.authorization, tool, message, issuer="operator", ttl_seconds=60
            )
        async with client(url, token) as peer:
            request = asyncio.create_task(peer.call_tool(tool, args, meta=key("owned-final")))
            try:
                await gate.wait()
                request.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await request
            finally:
                gate.release.set()
            await asyncio.wait_for(completed.wait(), 3)
            reply = await peer.call_tool(tool, args, meta=key("owned-final"))
            assert reply.meta and reply.meta["mcp-agent-server/replayed"] is True
        with AuditStore(audit_db).transaction() as db:
            assert db.execute("select state from operations").fetchall() == [("COMPLETED",)]
            assert (
                db.execute("select count(*) from audit_events where phase='post'").fetchone()[0]
                == 1
            )
            assert db.execute("select count(consumed_event) from approvals").fetchone()[0] == (
                1 if tool == "send_message" else 0
            )
        with sqlite3.connect(audit_db) as db:
            assert db.execute("select count(*) from notes").fetchone()[0] == (
                1 if tool == "write_note" else 0
            )
        assert len(outbox.entries) == (1 if tool == "send_message" else 0)
    assert pipe.persistence.pending == 0
