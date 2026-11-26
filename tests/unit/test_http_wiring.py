from pathlib import Path

import pytest

from mcp_agent_server.config import Settings
from mcp_agent_server.server import create_server
from mcp_agent_server.transport.context import Clients
from mcp_agent_server.transport.http import HTTPApplication


def test_http_cannot_wrap_stdio_context(audit_db: Path) -> None:
    cfg = Settings(audit_db=audit_db)
    clients = Clients(cfg.http)
    with pytest.raises(ValueError, match="trusted context"):
        HTTPApplication(create_server(cfg), cfg, clients)
