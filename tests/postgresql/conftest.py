import os
import subprocess
import time
from collections.abc import Iterator
from uuid import uuid4

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from pydantic import SecretStr

from mcp_agent_server.config import Settings
from mcp_agent_server.storage.migrate import migrate
from mcp_agent_server.storage.postgres import PostgresStore

IMAGE = "pgvector/pgvector@sha256:40b404964359299eefdd5f8518facf1886c562848cf4de13b6eaf91cb70c2b87"


def docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True, timeout=45
    ).stdout.strip()


@pytest.fixture(scope="session")
def postgres() -> Iterator[dict[str, str]]:
    name = "mcp-pg-test-" + uuid4().hex[:12]
    managed = "MCP_TEST_POSTGRES_PORT" not in os.environ
    if managed:
        docker(
            "run",
            "--pull=never",
            "--rm",
            "-d",
            "--name",
            name,
            "--memory=256m",
            "--cpus=1",
            "--pids-limit=128",
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e",
            "POSTGRES_DB=mcp_test",
            "-p",
            "127.0.0.1::5432",
            IMAGE,
        )
    try:
        port = (
            docker("port", name, "5432/tcp").rsplit(":", 1)[1]
            if managed
            else os.environ["MCP_TEST_POSTGRES_PORT"]
        )
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("Invalid local test database port")
        params = dict(
            host="127.0.0.1",
            port=port,
            user="postgres",
            password="synthetic",
            dbname="mcp_test",
            sslmode="disable",
            connect_timeout="1",
        )
        deadline = time.monotonic() + 20
        while True:
            try:
                with psycopg.connect(make_conninfo(**params), autocommit=True) as db:
                    db.execute("CREATE ROLE mcp_runtime LOGIN")
                break
            except psycopg.OperationalError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)  # Readiness polling only; cancellation tests use barriers.
        migrate(params)
        with psycopg.connect(make_conninfo(**params), autocommit=True) as db:
            db.execute("GRANT USAGE ON SCHEMA mcp_agent TO mcp_runtime")
            db.execute("GRANT SELECT ON ALL TABLES IN SCHEMA mcp_agent TO mcp_runtime")
            db.execute(
                "GRANT INSERT ON mcp_agent.audit_events,mcp_agent.audit_policy,"
                "mcp_agent.operation_attempts,mcp_agent.notes,mcp_agent.simulations,"
                "mcp_agent.approvals,mcp_agent.operations TO mcp_runtime"
            )
            db.execute("GRANT UPDATE ON mcp_agent.approvals,mcp_agent.operations TO mcp_runtime")
            db.execute("GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA mcp_agent TO mcp_runtime")
        yield params
    finally:
        if managed:
            docker("rm", "-f", name)


@pytest.fixture
def pg_settings(postgres: dict[str, str]) -> Settings:
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
        db.execute(
            "TRUNCATE mcp_agent.approvals,mcp_agent.audit_events,mcp_agent.operations,"
            "mcp_agent.notes,mcp_agent.simulations RESTART IDENTITY CASCADE"
        )
    return Settings(
        environment="test",
        storage_backend="postgresql",
        database_url=SecretStr(
            f"postgresql://mcp_runtime:synthetic@127.0.0.1:{postgres['port']}/mcp_test?sslmode=disable"
        ),
    )


@pytest.fixture
def pg_store(pg_settings: Settings) -> Iterator[PostgresStore]:
    store = PostgresStore(pg_settings)
    try:
        yield store
    finally:
        store.close()
