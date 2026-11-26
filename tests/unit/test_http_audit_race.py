import os
from pathlib import Path

import pytest

from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.config import audit_path


@pytest.mark.parametrize(
    "suffix,links,allowed",
    [
        ("-journal", 0, True),
        ("-wal", 0, True),
        ("-shm", 0, True),
        ("", 0, False),
        ("-journal", 2, False),
    ],
)
def test_transient_sidecar_unlink_preserves_link_protection(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch, suffix: str, links: int, allowed: bool
) -> None:
    AuditStore(audit_db)
    target = Path(str(audit_db) + suffix)
    if suffix:
        target.touch()
    original = Path.lstat

    def observed(path: Path) -> os.stat_result:
        value = original(path)
        if path == target:
            fields = list(value)
            fields[3] = links
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(Path, "lstat", observed)
    if allowed:
        assert audit_path(audit_db) == audit_db
    else:
        with pytest.raises(ValueError, match="without links"):
            audit_path(audit_db)
