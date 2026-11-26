import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import pytest

from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.errors import GuardrailError


def test_v1_upgrade_preserves_correlated_events(audit_db: Path) -> None:
    request, connection, first, second = (str(uuid4()) for _ in range(4))
    with closing(sqlite3.connect(audit_db)) as db, db:
        db.executescript((Path(__file__).parents[1] / "fixtures/audit_v1.sql").read_text())
        sql = "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
        for identifier, phase, status, parent in [
            (first, "pre", "not_executed", None),
            (second, "post", "succeeded", first),
        ]:
            db.execute(
                sql,
                (
                    identifier,
                    request,
                    "2026-01-01T00:00:00Z",
                    connection,
                    "health",
                    phase,
                    1,
                    "passed",
                    status,
                    None,
                    0.0,
                    "object:0",
                    parent,
                ),
            )
        before = db.execute("SELECT * FROM audit_events ORDER BY rowid").fetchall()
    AuditStore(audit_db)
    AuditStore(audit_db)
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("PRAGMA user_version").fetchone() == (4,)
        assert db.execute("SELECT * FROM audit_events ORDER BY rowid").fetchall() == before
        assert db.execute("SELECT count(*) FROM audit_policy").fetchone() == (0,)
        assert not db.execute("PRAGMA foreign_key_check").fetchall()


def test_corrupt_v1_is_not_migrated(audit_db: Path) -> None:
    with closing(sqlite3.connect(audit_db)) as db, db:
        db.executescript("CREATE TABLE audit_events(private TEXT); PRAGMA user_version=1")
    with pytest.raises(GuardrailError):
        AuditStore(audit_db)
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("PRAGMA user_version").fetchone() == (1,)
        assert db.execute("SELECT name FROM sqlite_schema").fetchall() == [("audit_events",)]
