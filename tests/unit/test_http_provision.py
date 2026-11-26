import json
import stat
from pathlib import Path

import pytest

from mcp_agent_server.transport.context import Clients
from mcp_agent_server.transport.http import provision
from mcp_agent_server.transport.settings import HTTPSettings


def test_private_provision_and_unsafe_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("mcp_agent_server.transport.http.PROJECT", tmp_path)
    clients = Clients(HTTPSettings())
    path = provision(clients)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    values = json.loads(path.read_text())
    assert clients.authenticate("Bearer " + values["token"])
    clients.clear()
    assert clients.authenticate("Bearer " + values["token"]) is None
    path.unlink()
    path.parent.chmod(0o755)
    with pytest.raises(ValueError):
        provision(clients)
    path.parent.rmdir()
    path.parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        provision(clients)
