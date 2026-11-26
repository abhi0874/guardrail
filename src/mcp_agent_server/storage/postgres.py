"""Bounded PostgreSQL transactions, private namespace and safe driver diagnostics."""

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg_pool import ConnectionPool, PoolTimeout, TooManyRequests

from mcp_agent_server.audit.lifecycle import checkpoint
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.config import Settings
from mcp_agent_server.errors import ErrorCode, GuardrailError

from .connection import Connection
from .settings import connection_parameters


class SafeDriverLogs(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = "PostgreSQL pool connection unavailable"
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        return True


logging.getLogger("psycopg.pool").addFilter(SafeDriverLogs())


class Row:
    def __init__(self, values: tuple[Any, ...], names: tuple[str, ...]):
        self.values, self.names = values, names

    def __getitem__(self, key: int | str) -> Any:
        return self.values[self.names.index(key) if isinstance(key, str) else key]


class Cursor:
    def __init__(self, cursor: psycopg.Cursor[tuple[Any, ...]]):
        self.cursor = cursor

    @property
    def rowcount(self) -> int:
        return self.cursor.rowcount

    def fetchone(self) -> Any:
        value = self.cursor.fetchone()
        if value is None:
            return None
        assert self.cursor.description is not None
        return Row(value, tuple(c.name for c in self.cursor.description))

    def fetchall(self) -> list[Any]:
        assert self.cursor.description is not None
        names = tuple(c.name for c in self.cursor.description)
        return [Row(value, names) for value in self.cursor.fetchall()]


class PostgresConnection:
    # Compatibility with trusted storage callers selecting named SQLite rows.
    row_factory: Any = None

    def __init__(self, connection: psycopg.Connection[tuple[Any, ...]]):
        self.connection = connection

    def execute(self, sql: str, parameters: Any = (), /) -> Cursor:
        # Only repository-owned SQL reaches here. Values always stay driver-bound.
        # The shared contract uses qmark / named DB-API bindings, never interpolation.
        sql = sql.replace("?", "%s")
        sql = re.sub(r"(?<!:):([a-z_]+)\b", r"%(\1)s", sql)
        sql = sql.replace(
            "q.approval_ref IS p.approval_ref", "q.approval_ref IS NOT DISTINCT FROM p.approval_ref"
        )
        sql = sql.replace("ORDER BY rowid DESC", "ORDER BY approval_order DESC")
        if isinstance(parameters, dict):
            parameters = {k: int(v) if isinstance(v, bool) else v for k, v in parameters.items()}
        else:
            parameters = tuple(int(v) if isinstance(v, bool) else v for v in parameters)
        return Cursor(self.connection.execute(sql, parameters or None, prepare=False))


class PostgresStore(AuditStore):
    def __init__(self, settings: Settings):
        parameters = connection_parameters(
            settings.database_url, production=settings.environment == "production"
        )
        self.pool = ConnectionPool(
            kwargs={**parameters, "prepare_threshold": None, "autocommit": True},
            min_size=0,
            max_size=settings.db_pool_size,
            max_waiting=32,
            timeout=2,
            reconnect_timeout=2,
            num_workers=1,
            open=True,
            check=ConnectionPool.check_connection,
        )
        try:
            with self.transaction() as db:
                from .migrate import verify

                verify(db)
                role = db.execute(
                    "SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls "
                    "FROM pg_roles WHERE rolname=current_user"
                ).fetchone()
                if role is None or any(role[i] for i in range(4)):
                    raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
                if db.execute(
                    "SELECT has_schema_privilege(current_user,'mcp_agent','CREATE')"
                ).fetchone()[0]:
                    raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
        except BaseException:
            self.close()
            raise

    @contextmanager
    def transaction(self, *, create: bool = False, lock_timeout: float = 2) -> Iterator[Connection]:
        if create:
            raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
        try:
            checkpoint()
            with self.pool.connection(timeout=max(0.001, min(2, lock_timeout))) as connection:
                # Explicit transaction: no connection/session-level state, retry or
                # implicit SQLite-wide lock. Compatible with transaction poolers.
                with connection.transaction():
                    db = PostgresConnection(connection)
                    # One round trip, with the same transaction-local safeguards.
                    # Finish setup before yielding: no effect can precede a setup error.
                    db.execute(
                        "SELECT set_config('search_path','pg_catalog,mcp_agent',true),"
                        "set_config('statement_timeout','2000',true),"
                        "set_config('lock_timeout',?,true),"
                        "set_config('idle_in_transaction_session_timeout','2500',true),"
                        "set_config('synchronous_commit','on',true)",
                        (str(max(1, int(min(2, lock_timeout) * 1000))),),
                    )
                    yield db
                    checkpoint()
        except (psycopg.Error, PoolTimeout, TooManyRequests, OSError, ValueError):
            # A failed COMMIT may be ambiguous. The mutation service retains the
            # reservation and surfaces an integrity/unknown result, never retries.
            raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE) from None

    def close(self) -> None:
        self.pool.close(timeout=2)
