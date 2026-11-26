import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from pydantic import SecretStr, ValidationError

from mcp_agent_server.adapters.notes import insert_note
from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.config import Settings
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.approval import ApprovalGate, Binding
from mcp_agent_server.guardrails.authorization import LOCAL, AuthorizationContext
from mcp_agent_server.guardrails.models import GuardrailRequest, Status, Validation
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.guardrails.policy import load_policy
from mcp_agent_server.storage.factory import create_store
from mcp_agent_server.storage.migrate import main, migrate, migrations, verify
from mcp_agent_server.storage.postgres import PostgresStore
from mcp_agent_server.storage.settings import connection_parameters
from mcp_agent_server.tools.models import Message, NoteReceipt
from mcp_agent_server.tools.registry import SPECS


def pipeline(store: PostgresStore) -> Pipeline:
    return Pipeline(
        store,
        {k: s.arguments for k, s in SPECS.items()},
        8192,
        8,
        mutations={k: s.mutation for k, s in SPECS.items() if s.mutation},
    )


async def note(pipe: Pipeline, *, connection: Any = None, key: str = "one-note") -> Any:
    async def dispatch(data: Any) -> dict[str, object]:
        with pipe.handler("write_note"):
            assert pipe.mutation_service is not None
            receipt = await pipe.mutation_service.local_effect(
                lambda db: insert_note(db, data.title, data.body)
            )
            assert isinstance(receipt, NoteReceipt)
            return {"structuredContent": receipt.model_dump()}

    return await pipe.execute(
        GuardrailRequest(
            connection_id=connection or uuid4(),
            tool_name="write_note",
            arguments={"title": "Synthetic note", "body": "Persistent test value"},
        ),
        dispatch,
        idempotency_key=key,
    )


def test_migrations_restart_and_least_privilege(
    pg_store: PostgresStore, postgres: dict[str, str], pg_settings: Settings
) -> None:
    migrate(postgres)  # Idempotent, real DDL and checksums.
    assert len(migrations()) == 2
    with pg_store.transaction() as db:
        verify(db)
        assert insert_note(db, "Persistent", "After restart").note_id > 0
    reopened = create_store(pg_settings)
    try:
        with reopened.transaction() as db:
            assert db.execute("SELECT body FROM notes").fetchone()[0] == "After restart"
        with pytest.raises(GuardrailError):
            with reopened.transaction() as db:
                db.execute("CREATE TABLE forbidden (x INTEGER)")
        with pytest.raises(GuardrailError):
            with reopened.transaction() as db:
                db.execute("DELETE FROM notes")
        with pytest.raises(GuardrailError):
            with reopened.transaction(create=True):
                pass
    finally:
        reopened.close()


def test_migration_checksum_failure(pg_store: PostgresStore, postgres: dict[str, str]) -> None:
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
        db.execute("UPDATE mcp_agent.schema_migrations SET checksum='changed' WHERE version=2")
    try:
        with pytest.raises(GuardrailError):
            migrate(postgres)
        with pytest.raises(GuardrailError):
            with pg_store.transaction() as db:
                verify(db)
    finally:
        with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
            db.execute(
                "UPDATE mcp_agent.schema_migrations SET checksum=%s WHERE version=2",
                (migrations()[1][1],),
            )


def test_rollback_and_bound_parameters(pg_store: PostgresStore) -> None:
    marker = "x'); DROP TABLE notes; --"
    with pytest.raises(RuntimeError):
        with pg_store.transaction() as db:
            insert_note(db, marker, "rollback")
            raise RuntimeError("synthetic rollback")
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0
        insert_note(db, marker, "literal")
    with pg_store.transaction() as db:
        assert db.execute("SELECT title FROM notes").fetchone()[0] == marker


@pytest.mark.asyncio
async def test_note_replay_and_client_binding(pg_store: PostgresStore) -> None:
    pipe = pipeline(pg_store)
    client = uuid4()
    first, value = await note(pipe, connection=client)
    assert first.error is None and value
    replay, same = await note(pipe, connection=client)
    assert replay.error is None and replay.status == "replayed"
    assert same["structuredContent"] == value["structuredContent"]
    other, response = await note(pipe)
    assert (
        other.error and other.error.code == ErrorCode.IDEMPOTENCY_KEY_CONFLICT and response is None
    )
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT state FROM operations").fetchone()[0] == "COMPLETED"
        assert db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone()[0] == 1
    await pipe.persistence.aclose()


@pytest.mark.asyncio
async def test_concurrent_idempotent_effect(pg_store: PostgresStore) -> None:
    pipes = [pipeline(pg_store) for _ in range(8)]
    client = uuid4()
    results = await asyncio.gather(*(note(p, connection=client) for p in pipes))
    assert any(r.error is None for r, _ in results)
    assert all(
        r.error is None or r.error.code == ErrorCode.OPERATION_IN_PROGRESS for r, _ in results
    )
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == 1
    for p in pipes:
        await p.persistence.aclose()


def test_concurrent_approval_single_use(pg_store: PostgresStore) -> None:
    policy = load_policy()
    gate = ApprovalGate(pg_store, policy)
    context = AuthorizationContext(connection_id=uuid4(), identity=LOCAL)
    message = Message(recipient="ops-lab", subject="Synthetic", body="Approval test")
    token = gate.issue(context, "send_message", message, issuer="operator", ttl_seconds=60)
    binding = Binding.create(context, "send_message", message, policy)

    def consume(_: int) -> str:
        event = AuditEvent(
            request_id=uuid4(),
            error_code=None,
            connection_id=context.connection_id,
            tool_name="send_message",
            phase="pre",
            allowed=True,
            validation=Validation.PASSED,
            status=Status.NOT_EXECUTED,
            duration_ms=0,
            argument_summary="synthetic",
            policy_digest=policy.digest,
            principal=LOCAL.principal,
            approval_required=True,
        )
        try:
            gate.consume(event, binding, token)
            return "consumed"
        except GuardrailError as e:
            return e.public.code

    with ThreadPoolExecutor(max_workers=6) as workers:
        results = list(workers.map(consume, range(6)))
    assert results.count("consumed") == 1 and results.count(ErrorCode.APPROVAL_USED) == 5
    with pg_store.transaction() as db:
        assert (
            db.execute("SELECT count(*) FROM approvals WHERE consumed_at IS NOT NULL").fetchone()[0]
            == 1
        )
        assert db.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 1
    gate.revoke(gate.issue(context, "send_message", message, issuer="operator", ttl_seconds=60))


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ["before", "post", "committed"])
async def test_cancellation_durability(
    pg_store: PostgresStore, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    pipe = pipeline(pg_store)
    entered = threading.Event()
    release = threading.Event()
    client = uuid4()
    assert pipe.mutation_service is not None
    operations = pipe.mutation_service.store
    original = operations.finish if where != "before" else operations.start

    def blocked(*args: Any) -> None:
        if where == "committed":
            original(*args)
        entered.set()
        assert release.wait(3)
        if where != "committed":
            original(*args)

    monkeypatch.setattr(operations, "start" if where == "before" else "finish", blocked)
    task = asyncio.create_task(note(pipe, connection=client))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        for _ in range(3):
            task.cancel()
            barrier = asyncio.Event()
            asyncio.get_running_loop().call_soon(barrier.set)
            await barrier.wait()
            assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await pipe.persistence.aclose()
    assert pipe.persistence.pending == 0
    with pg_store.transaction() as db:
        state = db.execute("SELECT state FROM operations").fetchone()[0]
        assert state == ("OUTCOME_UNKNOWN" if where == "before" else "COMPLETED")
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == (
            0 if where == "before" else 1
        )
        assert db.execute("SELECT count(*) FROM audit_events WHERE phase='post'").fetchone()[0] == 1
    again, result = await note(pipe=pipeline(pg_store), connection=client)
    assert (
        (again.error and result is None) if where == "before" else (again.error is None and result)
    )
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == (
            0 if where == "before" else 1
        )


@pytest.mark.asyncio
async def test_committed_lost_response_never_reexecutes(
    pg_store: PostgresStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipe = pipeline(pg_store)
    client = uuid4()
    assert pipe.mutation_service
    store = pipe.mutation_service.store
    original = store.local_effect

    def lose(*args: Any) -> object:
        original(*args)
        raise OSError("synthetic lost reply")

    monkeypatch.setattr(store, "local_effect", lose)
    failure, value = await note(pipe, connection=client)
    assert (
        failure.error
        and failure.error.code == ErrorCode.OPERATION_OUTCOME_UNKNOWN
        and value is None
    )
    again, result = await note(pipe, connection=client)
    assert (
        again.error and again.error.code == ErrorCode.OPERATION_OUTCOME_UNKNOWN and result is None
    )
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT state FROM operations").fetchone()[0] == "OUTCOME_UNKNOWN"
    await pipe.persistence.aclose()


def test_broken_connection_reconnects(
    pg_store: PostgresStore, postgres: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    with pg_store.transaction() as db:
        pid = db.execute("SELECT pg_backend_pid()").fetchone()[0]
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as admin:
        admin.execute("SELECT pg_terminate_backend(%s)", (pid,))
    with pg_store.transaction() as db:
        assert db.execute("SELECT pg_backend_pid()").fetchone()[0] != pid
    assert "synthetic@" not in caplog.text and "password=" not in caplog.text


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "postgresql://x",
        "postgresql://u:p@remote/db?sslmode=disable",
        "postgresql://u:p@remote/db?options=bad",
        "postgresql://u:p@remote/db?sslmode=require",
        "postgresql://u:p@127.0.0.1/db?sslmode=disable",
    ],
)
def test_production_fail_closed(raw: str | None) -> None:
    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            storage_backend="postgresql",
            database_url=SecretStr(raw) if raw is not None else None,
        )


def test_config_secret_projection_and_migration_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production")
    with pytest.raises(ValidationError):
        Settings(database_url=SecretStr("secret"))
    settings = Settings.from_env(
        {
            "MCP_AGENT_ENVIRONMENT": "production",
            "MCP_AGENT_STORAGE_BACKEND": "postgresql",
            "MCP_AGENT_DATABASE_URL": "postgresql://runtime:synthetic-credential@db.example.test/postgres?sslmode=verify-full",
        }
    )
    assert "synthetic-credential" not in repr(settings) + settings.model_dump_json()
    assert (
        settings.database_url
        and connection_parameters(settings.database_url, production=True)["sslmode"]
        == "verify-full"
    )
    monkeypatch.setenv("MCP_AGENT_MIGRATION_URL", "synthetic-invalid-secret")
    assert main() == 1
    assert "synthetic-invalid-secret" not in capsys.readouterr().err


def test_additive_upgrade_and_unknown_version(
    pg_store: PostgresStore, postgres: dict[str, str], pg_settings: Settings
) -> None:
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
        db.execute("DROP TABLE mcp_agent.simulations")
        db.execute("DELETE FROM mcp_agent.schema_migrations WHERE version=2")
    migrate(postgres)
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
        db.execute("GRANT SELECT,INSERT ON mcp_agent.simulations TO mcp_runtime")
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM simulations").fetchone()[0] == 0
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
        db.execute("INSERT INTO mcp_agent.schema_migrations VALUES (999,'unsupported')")
    try:
        with pytest.raises(GuardrailError):
            PostgresStore(pg_settings)
    finally:
        with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
            db.execute("DELETE FROM mcp_agent.schema_migrations WHERE version=999")


def test_owner_credentials_refused(
    pg_store: PostgresStore, pg_settings: Settings, postgres: dict[str, str]
) -> None:
    owner = pg_settings.model_copy(
        update={
            "database_url": SecretStr(
                f"postgresql://postgres:synthetic@127.0.0.1:{postgres['port']}/mcp_test?sslmode=disable"
            )
        }
    )
    with pytest.raises(GuardrailError):
        PostgresStore(owner)
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
        db.execute("GRANT CREATE ON SCHEMA mcp_agent TO mcp_runtime")
    try:
        with pytest.raises(GuardrailError):
            PostgresStore(pg_settings)
    finally:
        with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
            db.execute("REVOKE CREATE ON SCHEMA mcp_agent FROM mcp_runtime")


@pytest.mark.asyncio
async def test_audit_failure_after_committed_note_is_unknown(
    pg_store: PostgresStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipe = pipeline(pg_store)
    assert pipe.mutation_service

    def fail_finish(*args: Any) -> None:
        with pg_store.transaction() as db:
            db.execute("SELECT pg_terminate_backend(pg_backend_pid())")

    monkeypatch.setattr(pipe.mutation_service.store, "finish", fail_finish)
    client = uuid4()
    result, value = await note(pipe, connection=client)
    assert result.error and result.error.code == ErrorCode.AUDIT_INTEGRITY and value is None
    again, value = await note(pipe, connection=client)
    assert again.error and again.error.code == ErrorCode.OPERATION_OUTCOME_UNKNOWN and value is None
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
        assert db.execute("SELECT state FROM operations").fetchone()[0] == "OUTCOME_UNKNOWN"
        assert (
            db.execute("SELECT status FROM audit_events WHERE phase='post'").fetchone()[0]
            == "interrupted"
        )
    await pipe.persistence.aclose()


@pytest.mark.asyncio
async def test_cancelled_transaction_rolls_back(pg_store: PostgresStore) -> None:
    pipe = pipeline(pg_store)
    started = threading.Event()
    release = threading.Event()

    def operation() -> None:
        with pg_store.transaction() as db:
            insert_note(db, "Synthetic rollback", "Never durable")
            started.set()
            assert release.wait(3)
            raise OSError("synthetic storage failure")

    task = asyncio.create_task(pipe.persistence.run(operation))
    try:
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        barrier = asyncio.Event()
        asyncio.get_running_loop().call_soon(barrier.set)
        await barrier.wait()
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(GuardrailError):
        await task
    await pipe.persistence.aclose()
    assert pipe.persistence.pending == 0
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0


def test_missing_database_safe_failure(
    pg_settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        cfg = pg_settings.model_copy(
            update={
                "database_url": SecretStr(
                    f"postgresql://runtime:synthetic-only@127.0.0.1:{port}/missing?sslmode=disable"
                )
            }
        )
        with pytest.raises(GuardrailError) as error:
            PostgresStore(cfg)
    assert error.value.public.code == ErrorCode.AUDIT_UNAVAILABLE
    assert "synthetic-only" not in str(error.value) + caplog.text


def test_migration_cli_success_does_not_echo_secrets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import mcp_agent_server.storage.migrate as module

    received = []
    monkeypatch.setattr(module, "migrate", lambda params: received.append(params["sslmode"]))
    monkeypatch.setenv(
        "MCP_AGENT_MIGRATION_URL",
        "postgresql://runtime:synthetic-only@db.example.test/db?sslmode=verify-full",
    )
    assert module.main() == 0 and received == ["verify-full"]
    assert "synthetic-only" not in capsys.readouterr().out


@pytest.mark.asyncio
async def test_expired_postgres_commit_is_fenced(
    pg_store: PostgresStore, caplog: pytest.LogCaptureFixture
) -> None:
    from mcp_agent_server.audit.lifecycle import Persistence

    supervisor = Persistence(0.1)
    entered = threading.Event()
    release = threading.Event()

    def operation() -> None:
        with pg_store.transaction() as db:
            insert_note(db, "Expired write", "Must roll back")
            entered.set()
            assert release.wait(3)

    task = asyncio.create_task(supervisor.run(operation))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        with pytest.raises(GuardrailError) as error:
            await task
        assert error.value.public.code == ErrorCode.AUDIT_INTEGRITY and supervisor.pending == 1
        with pytest.raises(GuardrailError):
            await supervisor.run(lambda: None)
    finally:
        release.set()
    await supervisor.aclose()
    assert supervisor.pending == 0
    with pg_store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0
    assert "Persistence deadline exceeded" in caplog.text
    assert "Expired persistence worker failed" in caplog.text


def test_production_cli_configuration_error_is_safe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mcp_agent_server.server import main as server_main

    monkeypatch.setenv("MCP_AGENT_ENVIRONMENT", "production")
    monkeypatch.delenv("MCP_AGENT_STORAGE_BACKEND", raising=False)
    monkeypatch.delenv("MCP_AGENT_DATABASE_URL", raising=False)
    assert server_main() == 2
    captured = capsys.readouterr()
    assert (
        not captured.out and "invalid_configuration" in captured.err and "storage" in captured.err
    )
    assert "Traceback" not in captured.err


def test_missing_packaged_migration_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import mcp_agent_server.storage.migrate as module

    monkeypatch.setattr(module, "DIRECTORY", tmp_path)
    with pytest.raises(GuardrailError) as error:
        module.migrations()
    assert error.value.public.code == ErrorCode.AUDIT_UNAVAILABLE
