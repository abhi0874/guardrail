import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from mcp_agent_server.audit.models import AuditEvent
from mcp_agent_server.audit.storage import SCHEMA_VERSION, AuditStore
from mcp_agent_server.config import Settings
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.models import Status, Validation


def event() -> AuditEvent:
    return AuditEvent(
        request_id=uuid4(),
        connection_id=uuid4(),
        tool_name="health",
        phase="pre",
        allowed=True,
        validation=Validation.PASSED,
        status=Status.NOT_EXECUTED,
        error_code=None,
        duration_ms=0,
        argument_summary="object:0",
    )


def test_append_only_parameter_binding_and_foreign_key(audit_db: Path) -> None:
    store = AuditStore(audit_db)
    first = event().model_copy(update={"tool_name": "x'); DROP TABLE audit_events;--"})
    store.append(first)
    with pytest.raises(GuardrailError):
        store.append(first)
    orphan = event().model_copy(update={"phase": "post", "parent_event_id": first.event_id})
    with pytest.raises(GuardrailError):
        store.append(orphan)
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("PRAGMA user_version").fetchone() == (SCHEMA_VERSION,)
        [(label, timestamp)] = db.execute("SELECT tool_name,timestamp FROM audit_events")
        assert (
            label == first.tool_name
            and datetime.fromisoformat(timestamp).utcoffset() == timedelta()
        )


def test_concurrent_transactions(audit_db: Path) -> None:
    store = AuditStore(audit_db)
    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(store.append, (event() for _ in range(40))))
    with closing(sqlite3.connect(audit_db)) as db:
        assert db.execute("SELECT count(DISTINCT event_id) FROM audit_events").fetchone() == (40,)
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)


@pytest.mark.parametrize(
    "sql", ["PRAGMA user_version=17", "CREATE TABLE unrelated(x)", "CREATE TABLE audit_events(x)"]
)
def test_reject_unknown_or_unversioned_database(audit_db: Path, sql: str) -> None:
    with closing(sqlite3.connect(audit_db)) as db:
        db.execute(sql)
    with pytest.raises(GuardrailError) as exc:
        AuditStore(audit_db)
    assert exc.value.public.code == ErrorCode.AUDIT_UNAVAILABLE


def test_recheck_on_append_and_no_accidental_recreation(audit_db: Path) -> None:
    store = AuditStore(audit_db)
    with closing(sqlite3.connect(audit_db)) as db:
        db.execute("ALTER TABLE audit_events ADD COLUMN unexpected TEXT")
    with pytest.raises(GuardrailError):
        store.append(event())
    audit_db.unlink()
    with pytest.raises(GuardrailError):
        store.append(event())
    assert not audit_db.exists()


@pytest.mark.parametrize(
    "value",
    [
        "../escape.sqlite3",
        ".runtime/audit/../escape.sqlite3",
        ".runtime/audit/README.md",
        "src/unauthorized.sqlite3",
    ],
)
def test_path_confinement(value: str) -> None:
    with pytest.raises(ValidationError):
        Settings.from_env({"MCP_AGENT_AUDIT_DB": value})


def test_reject_linked_files_and_sidecars(audit_db: Path) -> None:
    real = audit_db.parent / "private"
    real.touch()
    audit_db.symlink_to(real)
    with pytest.raises(ValidationError):
        Settings(audit_db=audit_db)
    audit_db.unlink()
    os.link(real, audit_db)
    with pytest.raises(ValidationError):
        Settings(audit_db=audit_db)
    audit_db.unlink()
    Path(str(audit_db) + "-journal").symlink_to(real)
    with pytest.raises(GuardrailError):
        AuditStore(audit_db)


@pytest.mark.parametrize(
    "key,value",
    [
        ("MCP_AGENT_MAX_ARGUMENT_BYTES", "1"),
        ("MCP_AGENT_MAX_ARGUMENT_DEPTH", "65"),
        ("MCP_AGENT_MAX_ARGUMENT_DEPTH", "word"),
    ],
)
def test_config_rejects_bad_limits(key: str, value: str) -> None:
    with pytest.raises(ValidationError):
        Settings.from_env({key: value})
