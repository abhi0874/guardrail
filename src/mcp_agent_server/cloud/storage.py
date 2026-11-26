"""Operator-created session identity; no public registration or filesystem state."""

import hashlib
import math
import time
from pathlib import Path
from uuid import UUID

import psycopg

from mcp_agent_server.audit.lifecycle import Persistence
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.storage.postgres import PostgresStore

from .settings import ClientGrant

SQL = Path(__file__).with_name("sessions.sql")


class Sessions:
    def __init__(self, store: PostgresStore):
        self.store = store
        self.persistence = Persistence()

    def register(self, grants: tuple[ClientGrant, ...]) -> None:
        with self.store.transaction() as db:
            expected = hashlib.sha256(SQL.read_bytes()).hexdigest()
            rows = db.execute(
                "SELECT version, checksum FROM mcp_cloud.schema_migrations ORDER BY version"
            ).fetchall()
            if [(r[0], r[1]) for r in rows] != [(1, expected)]:
                raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
            for grant in grants:
                now = time.time()
                db.execute(
                    "INSERT INTO mcp_cloud.sessions VALUES (?,?,?,?) ON CONFLICT(session_id) "
                    "DO UPDATE SET credential_digest=excluded.credential_digest,"
                    "updated=excluded.updated",
                    (str(grant.identifier), digest(grant.token.get_secret_value()), now, now),
                )

    def touch(self, identifier: UUID, credential: str) -> None:
        with self.store.transaction() as db:
            if (
                db.execute(
                    "UPDATE mcp_cloud.sessions SET updated=? "
                    "WHERE session_id=? AND credential_digest=?",
                    (time.time(), str(identifier), credential),
                ).rowcount
                != 1
            ):
                raise GuardrailError(ErrorCode.TOOL_NOT_PERMITTED)


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def migrate_cloud(
    parameters: dict[str, str], *, lock_seconds: float = 2, statement_seconds: float = 5
) -> None:
    if not all(math.isfinite(v) and 0.01 <= v <= 60 for v in (lock_seconds, statement_seconds)):
        raise ValueError("Migration budgets must be between .01 and 60 seconds")
    from psycopg.conninfo import make_conninfo

    with psycopg.connect(
        make_conninfo(**parameters), autocommit=True, prepare_threshold=None
    ) as db:
        with db.transaction():
            db.execute(
                "SELECT set_config('lock_timeout',%s,true)", (str(int(lock_seconds * 1000)),)
            )
            db.execute(
                "SELECT set_config('statement_timeout',%s,true)",
                (str(int(statement_seconds * 1000)),),
            )
            db.execute("SELECT pg_advisory_xact_lock(773510092)")
            db.execute("CREATE SCHEMA IF NOT EXISTS mcp_cloud")
            db.execute("REVOKE ALL ON SCHEMA mcp_cloud FROM PUBLIC")
            db.execute(
                "CREATE TABLE IF NOT EXISTS mcp_cloud.schema_migrations("
                "version INTEGER PRIMARY KEY,checksum TEXT NOT NULL)"
            )
            rows = db.execute(
                "SELECT version,checksum FROM mcp_cloud.schema_migrations ORDER BY version"
            ).fetchall()
            expected = hashlib.sha256(SQL.read_bytes()).hexdigest()
            if rows and rows != [(1, expected)]:
                raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
            if not rows:
                db.execute(SQL.read_text(), prepare=False)
                db.execute("INSERT INTO mcp_cloud.schema_migrations VALUES (1,%s)", (expected,))
            db.execute("REVOKE ALL ON ALL TABLES IN SCHEMA mcp_cloud FROM PUBLIC")
