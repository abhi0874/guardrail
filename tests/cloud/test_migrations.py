import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from mcp_agent_server.cloud.app import CloudApplication
from mcp_agent_server.cloud.runtime import main
from mcp_agent_server.cloud.storage import migrate_cloud
from mcp_agent_server.errors import GuardrailError
from mcp_agent_server.storage.migrate import migrate, migrations


@pytest.mark.parametrize("budget", ["lock", "statement"])
def test_migration_wait_is_database_bounded(postgres: dict[str, str], budget: str) -> None:
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as blocker:
        with blocker.transaction():
            blocker.execute("SELECT pg_advisory_xact_lock(773510091)")
            started = time.monotonic()
            with pytest.raises(psycopg.Error) as failure:
                migrate(
                    postgres,
                    lock_seconds=0.05 if budget == "lock" else 1,
                    statement_seconds=0.05 if budget == "statement" else 1,
                )
            assert time.monotonic() - started < 1
            assert isinstance(
                failure.value,
                psycopg.errors.LockNotAvailable
                if budget == "lock"
                else psycopg.errors.QueryCanceled,
            )
    migrate(postgres)


def test_concurrent_migrations_and_interrupted_ddl(
    postgres: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert list(executor.map(lambda _: migrate(postgres), range(2))) == [None, None]
    import mcp_agent_server.storage.migrate as module

    original = migrations()
    monkeypatch.setattr(
        module,
        "migrations",
        lambda: (
            original
            + [
                (
                    3,
                    "synthetic",
                    "CREATE TABLE mcp_agent.interrupted_test(x INTEGER); SELECT pg_sleep(2);",
                )
            ]
        ),
    )
    with pytest.raises(psycopg.errors.QueryCanceled):
        migrate(postgres, statement_seconds=0.05)
    with psycopg.connect(make_conninfo(**postgres)) as db:
        row = db.execute("SELECT to_regclass('mcp_agent.interrupted_test')").fetchone()
        assert row is not None and row[0] is None
        row = db.execute("SELECT count(*) FROM mcp_agent.schema_migrations").fetchone()
        assert row is not None and row[0] == 2


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), 61])
def test_invalid_migration_budgets(value: float) -> None:
    with pytest.raises(ValueError):
        migrate({}, lock_seconds=value)
    with pytest.raises(ValueError):
        migrate_cloud({}, lock_seconds=value)


def test_cloud_migration_integrity(postgres: dict[str, str]) -> None:
    migrate_cloud(postgres)
    migrate_cloud(postgres)
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
        row = db.execute("SELECT checksum FROM mcp_cloud.schema_migrations").fetchone()
        assert row is not None
        old = row[0]
        db.execute("UPDATE mcp_cloud.schema_migrations SET checksum='bad'")
    try:
        with pytest.raises(GuardrailError):
            migrate_cloud(postgres)
    finally:
        with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
            db.execute("UPDATE mcp_cloud.schema_migrations SET checksum=%s", (old,))


def test_cloud_startup_safe_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MCP_AGENT_ENVIRONMENT", "production")
    monkeypatch.delenv("MCP_AGENT_DATABASE_URL", raising=False)
    assert main() == 1
    captured = capsys.readouterr()
    assert not captured.out and "failed safely" in captured.err


@pytest.mark.asyncio
async def test_registration_and_revocation_are_durable(cloud_app: CloudApplication) -> None:
    s = cloud_app.sessions
    grant = cloud_app.config.clients[0]
    with s.store.transaction() as db:
        row = db.execute(
            "SELECT credential_digest FROM mcp_cloud.sessions WHERE session_id=?",
            (str(grant.identifier),),
        ).fetchone()
        assert row and grant.token.get_secret_value() not in row[0]
    with pytest.raises(GuardrailError):
        s.touch(uuid4(), "not-a-credential")
    with s.store.transaction() as db:
        db.execute(
            "UPDATE mcp_cloud.sessions SET credential_digest='revoked' WHERE session_id=?",
            (str(grant.identifier),),
        )
    with pytest.raises(GuardrailError):
        s.touch(grant.identifier, row[0])


def test_cloud_migration_cli_budgets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import mcp_agent_server.cloud.migrate as module

    monkeypatch.delenv("MCP_AGENT_MIGRATION_URL", raising=False)
    assert module.main() == 1
    seen = []

    def migrate_stub(params: dict[str, str], **budgets: float) -> None:
        seen.append(budgets)

    monkeypatch.setattr(module, "migrate", migrate_stub)
    monkeypatch.setattr(module, "migrate_cloud", migrate_stub)
    monkeypatch.setenv(
        "MCP_AGENT_MIGRATION_URL",
        "postgresql://runtime:synthetic-only@db.example.test:5432/db?sslmode=verify-full",
    )
    monkeypatch.setenv("MCP_AGENT_MIGRATION_LOCK_SECONDS", ".2")
    monkeypatch.setenv("MCP_AGENT_MIGRATION_STATEMENT_SECONDS", "1")
    assert module.main() == 0 and seen == [{"lock_seconds": 0.2, "statement_seconds": 1.0}] * 2
    captured = capsys.readouterr()
    assert "synthetic-only" not in captured.out + captured.err
