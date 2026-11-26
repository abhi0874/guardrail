"""Explicit operator-only PostgreSQL migrations. Never run by tool dispatch."""

import hashlib
import math
import os
import sys
from pathlib import Path
from typing import Any

import psycopg
from psycopg.conninfo import make_conninfo
from pydantic import SecretStr

from mcp_agent_server.errors import ErrorCode, GuardrailError

from .settings import connection_parameters

DIRECTORY = Path(__file__).with_name("migrations")


def migrations() -> list[tuple[int, str, str]]:
    paths = sorted(DIRECTORY.glob("[0-9][0-9][0-9]_*.sql"))
    if [p.name for p in paths] != ["001_core.sql", "002_simulations.sql"]:
        raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
    return [
        (int(p.name[:3]), hashlib.sha256(p.read_bytes()).hexdigest(), p.read_text()) for p in paths
    ]


def verify(db: Any) -> None:
    expected = [(v, digest) for v, digest, _ in migrations()]
    rows = db.execute("SELECT version, checksum FROM schema_migrations ORDER BY version").fetchall()
    if [(r[0], r[1]) for r in rows] != expected:
        raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)


def migrate(
    parameters: dict[str, str], *, lock_seconds: float = 2, statement_seconds: float = 5
) -> None:
    if not all(math.isfinite(v) and 0.01 <= v <= 60 for v in (lock_seconds, statement_seconds)):
        raise ValueError("Migration timeouts must be between .01 and 60 seconds")
    with psycopg.connect(
        make_conninfo(**parameters), autocommit=True, prepare_threshold=None
    ) as connection:
        with connection.transaction():
            connection.execute(
                "SELECT set_config('lock_timeout',%s,true)", (str(int(lock_seconds * 1000)),)
            )
            connection.execute(
                "SELECT set_config('statement_timeout',%s,true)",
                (str(int(statement_seconds * 1000)),),
            )
            connection.execute("SELECT pg_advisory_xact_lock(773510091)")
            connection.execute("CREATE SCHEMA IF NOT EXISTS mcp_agent")
            connection.execute("REVOKE ALL ON SCHEMA mcp_agent FROM PUBLIC")
            connection.execute("SET LOCAL search_path = mcp_agent, pg_catalog")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations(\n"
                "version INTEGER PRIMARY KEY, checksum TEXT NOT NULL)"
            )
            rows = connection.execute(
                "SELECT version, checksum FROM schema_migrations ORDER BY version"
            ).fetchall()
            available = migrations()
            if rows != [(v, digest) for v, digest, _ in available[: len(rows)]]:
                raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
            for version, digest, sql in available[len(rows) :]:
                connection.execute(sql, prepare=False)
                connection.execute(
                    "INSERT INTO schema_migrations VALUES (%s,%s)", (version, digest)
                )
            connection.execute("REVOKE ALL ON ALL TABLES IN SCHEMA mcp_agent FROM PUBLIC")
            connection.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA mcp_agent FROM PUBLIC")
            connection.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcp_agent FROM PUBLIC")


def main() -> int:
    try:
        raw = os.environ.get("MCP_AGENT_MIGRATION_URL")
        parameters = connection_parameters(SecretStr(raw) if raw else None, production=True)
        lock = os.environ.get("MCP_AGENT_MIGRATION_LOCK_SECONDS")
        statement = os.environ.get("MCP_AGENT_MIGRATION_STATEMENT_SECONDS")
        if lock is None and statement is None:
            migrate(parameters)
        else:
            migrate(
                parameters,
                lock_seconds=float(lock or "2"),
                statement_seconds=float(statement or "5"),
            )
    except Exception:
        print(
            "PostgreSQL migration failed; inspect configuration and database privately.",
            file=sys.stderr,
        )
        return 1
    print("PostgreSQL migrations complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
