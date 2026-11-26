from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from mcp_agent_server.config import AUDIT_ROOT


@pytest.fixture
def audit_db() -> Iterator[Path]:
    AUDIT_ROOT.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=AUDIT_ROOT) as directory:
        yield Path(directory) / "events.sqlite3"
