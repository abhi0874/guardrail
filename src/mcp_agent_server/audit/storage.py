"""An append commits before returning. Connections are private to each transaction."""

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from mcp_agent_server.config import audit_path
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.idempotency.schema import ATTEMPTS, OPERATIONS, STATE_GUARD
from mcp_agent_server.storage.connection import Connection

from .lifecycle import checkpoint
from .models import AuditEvent

SCHEMA_VERSION = 4
_TABLE = """CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    request_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('pre','post','denied')),
    allowed INTEGER NOT NULL CHECK(allowed IN (0,1)),
    validation TEXT NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT,
    duration_ms REAL NOT NULL CHECK(duration_ms >= 0),
    argument_summary TEXT NOT NULL,
    parent_event_id TEXT,
    UNIQUE(request_id, phase), UNIQUE(request_id, event_id),
    CHECK((phase = 'post') = (parent_event_id IS NOT NULL)),
    FOREIGN KEY(request_id, parent_event_id) REFERENCES audit_events(request_id, event_id)
)"""
_APPROVALS = """CREATE TABLE approvals (
    reference TEXT PRIMARY KEY NOT NULL,
    token_digest TEXT NOT NULL UNIQUE,
    connection_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    arguments_digest TEXT NOT NULL,
    identity_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL CHECK(expires_at > issued_at),
    issuer TEXT NOT NULL,
    revoked_at REAL,
    consumed_at REAL,
    consumed_event TEXT UNIQUE REFERENCES audit_events(event_id),
    CHECK ((consumed_at IS NULL) = (consumed_event IS NULL))
)"""
_METADATA = """CREATE TABLE audit_policy (
    event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id),
    policy_digest TEXT NOT NULL,
    principal TEXT NOT NULL,
    approval_required INTEGER,
    approval_ref TEXT REFERENCES approvals(reference)
)"""
_V2 = {"audit_events": _TABLE, "approvals": _APPROVALS, "audit_policy": _METADATA}
_V3 = {
    **_V2,
    "operations": OPERATIONS,
    "operation_attempts": ATTEMPTS,
    "operation_state_guard": STATE_GUARD,
}
_NOTES = """CREATE TABLE notes (
    note_id INTEGER PRIMARY KEY, title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 120),
    body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 1500)
)"""
_V4 = {**_V3, "notes": _NOTES}
_INSERT = """INSERT INTO audit_events
(event_id,request_id,timestamp,connection_id,tool_name,phase,allowed,validation,status,
error_code,duration_ms,argument_summary,parent_event_id)
VALUES (:event_id,:request_id,:timestamp,:connection_id,:tool_name,:phase,:allowed,:validation,
:status,:error_code,:duration_ms,:argument_summary,:parent_event_id)"""


class AuditStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        with self.transaction(create=True):
            pass

    @contextmanager
    def transaction(self, *, create: bool = False, lock_timeout: float = 2) -> Iterator[Connection]:
        try:
            checkpoint()
            path = audit_path(self.path)
            if create:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            uri = path.as_uri() + ("?mode=rwc" if create else "?mode=rw")
            with closing(sqlite3.connect(uri, uri=True, timeout=lock_timeout)) as db, db:
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                version = db.execute("PRAGMA user_version").fetchone()[0]
                objects = db.execute(
                    "SELECT name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'"
                ).fetchall()
                if create and version == 0 and not objects:
                    db.execute(_TABLE)
                    version = 1
                    objects = [("audit_events", _TABLE)]
                if create and version == 1 and objects == [("audit_events", _TABLE)]:
                    db.execute(_APPROVALS)
                    db.execute(_METADATA)
                    version, objects = 2, list(_V2.items())
                if create and version == 2 and dict(objects) == _V2:
                    db.execute(OPERATIONS)
                    db.execute(ATTEMPTS)
                    db.execute(STATE_GUARD)
                    version, objects = 3, list(_V3.items())
                if create and version == 3 and dict(objects) == _V3:
                    db.execute(_NOTES)
                    db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                elif version != SCHEMA_VERSION or dict(objects) != _V4:
                    raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
                if create and db.execute("PRAGMA foreign_key_check").fetchone():
                    raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE)
                yield db
                checkpoint()
        except (OSError, sqlite3.Error, ValueError):
            raise GuardrailError(ErrorCode.AUDIT_UNAVAILABLE) from None

    def append(self, event: AuditEvent) -> None:
        with self.transaction() as db:
            self.insert_event(db, event)

    @staticmethod
    def insert_event(db: Connection, event: AuditEvent) -> None:
        values = event.model_dump(mode="json")
        db.execute(_INSERT, values)
        if event.policy_digest is not None:
            db.execute(
                "INSERT INTO audit_policy VALUES (:event_id,:policy_digest,:principal,"
                ":approval_required,:approval_ref)",
                values,
            )

    def close(self) -> None:
        """SQLite connections are already scoped to each transaction."""
