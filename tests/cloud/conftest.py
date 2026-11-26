import inspect
import os
import socket
from collections.abc import AsyncIterator, Callable, Iterator
from typing import cast
from uuid import uuid4

import psycopg
import pytest
import pytest_asyncio
from postgresql.conftest import pg_settings as original_settings
from postgresql.conftest import pg_store as pg_store
from postgresql.conftest import postgres as original_postgres
from psycopg.conninfo import make_conninfo
from pydantic import SecretStr

from mcp_agent_server.cloud.app import CloudApplication
from mcp_agent_server.cloud.runtime import application
from mcp_agent_server.cloud.settings import ClientGrant, CloudSettings
from mcp_agent_server.cloud.storage import migrate_cloud
from mcp_agent_server.config import Settings
from mcp_agent_server.storage.migrate import migrate


@pytest.fixture(scope="session")
def postgres() -> Iterator[dict[str, str]]:
    if "MCP_TEST_POSTGRES_PORT" not in os.environ:
        factory = cast(Callable[[], Iterator[dict[str, str]]], inspect.unwrap(original_postgres))
        yield from factory()
        return
    # CI shares one isolated server. Use a separate database/role so the original
    # Phase 1 fixture can initialize mcp_test/mcp_runtime independently.
    params = dict(
        host="127.0.0.1",
        port=os.environ["MCP_TEST_POSTGRES_PORT"],
        user="postgres",
        password="synthetic",
        dbname="postgres",
        sslmode="disable",
    )
    with psycopg.connect(make_conninfo(**params), autocommit=True) as db:
        db.execute("CREATE DATABASE cloud_test")
        db.execute("CREATE ROLE cloud_runtime LOGIN")
    params["dbname"] = "cloud_test"
    try:
        migrate(params)
        with psycopg.connect(make_conninfo(**params), autocommit=True) as db:
            db.execute("GRANT USAGE ON SCHEMA mcp_agent TO cloud_runtime")
            db.execute("GRANT SELECT ON ALL TABLES IN SCHEMA mcp_agent TO cloud_runtime")
            db.execute(
                "GRANT INSERT ON mcp_agent.audit_events,mcp_agent.audit_policy,"
                "mcp_agent.operation_attempts,mcp_agent.notes,mcp_agent.simulations,"
                "mcp_agent.approvals,mcp_agent.operations TO cloud_runtime"
            )
            db.execute("GRANT UPDATE ON mcp_agent.approvals,mcp_agent.operations TO cloud_runtime")
            db.execute("GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA mcp_agent TO cloud_runtime")
        yield params
    finally:
        params["dbname"] = "postgres"
        with psycopg.connect(make_conninfo(**params), autocommit=True) as db:
            db.execute("DROP DATABASE cloud_test WITH (FORCE)")
            db.execute("DROP ROLE cloud_runtime")


@pytest.fixture
def pg_settings(postgres: dict[str, str]) -> Settings:
    factory = cast(Callable[[dict[str, str]], Settings], inspect.unwrap(original_settings))
    cfg = factory(postgres)
    role = "cloud_runtime" if "MCP_TEST_POSTGRES_PORT" in os.environ else "mcp_runtime"
    return cfg.model_copy(
        update={
            "database_url": SecretStr(
                f"postgresql://{role}:synthetic@127.0.0.1:{postgres['port']}/{postgres['dbname']}?sslmode=disable"
            )
        }
    )


@pytest.fixture
def cloud_config() -> CloudSettings:
    return CloudSettings(
        hosts=("demo.example.test",),
        origins=("https://demo.example.test",),
        trusted_proxies=("127.0.0.1/32",),
        clients=(
            ClientGrant(identifier=uuid4(), token=SecretStr("A" * 43)),
            ClientGrant(identifier=uuid4(), token=SecretStr("B" * 43)),
        ),
    )


@pytest_asyncio.fixture
async def cloud_app(
    postgres: dict[str, str], pg_settings: Settings, cloud_config: CloudSettings
) -> AsyncIterator[CloudApplication]:
    migrate_cloud(postgres)
    with psycopg.connect(make_conninfo(**postgres), autocommit=True) as db:
        from psycopg import sql

        role = sql.Identifier(
            "cloud_runtime" if "MCP_TEST_POSTGRES_PORT" in os.environ else "mcp_runtime"
        )
        db.execute(sql.SQL("GRANT USAGE ON SCHEMA mcp_cloud TO {}").format(role))
        db.execute(sql.SQL("GRANT SELECT ON mcp_cloud.schema_migrations TO {}").format(role))
        db.execute(sql.SQL("GRANT SELECT,INSERT,UPDATE ON mcp_cloud.sessions TO {}").format(role))
        db.execute("TRUNCATE mcp_cloud.sessions")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    settings = pg_settings.model_copy(
        update={"http": pg_settings.http.model_copy(update={"enabled": True, "port": port})}
    )
    async with application(settings, cloud_config) as app:
        yield app
