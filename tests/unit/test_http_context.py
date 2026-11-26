import math
from uuid import uuid4

import pytest
from pydantic import ValidationError
from starlette.requests import Request

from mcp_agent_server.config import Settings
from mcp_agent_server.transport.context import Clients
from mcp_agent_server.transport.settings import HTTPSettings


@pytest.mark.parametrize(
    "data",
    [
        {"host": "0.0.0.0"},
        {"host": "::"},
        {"host": "192.168.1.1"},
        {"port": 80},
        {"port": 65536},
        {"ttl_seconds": 0},
        {"ttl_seconds": math.inf},
        {"max_clients": 0},
        {"max_body_bytes": 0},
    ],
)
def test_http_config_rejects_unsafe_values(data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        HTTPSettings.model_validate(data)


def test_http_opt_in_and_defaults() -> None:
    assert Settings().transport == "stdio" and not Settings().http.enabled
    config = Settings.from_env({"MCP_AGENT_HTTP_ENABLED": "true", "MCP_AGENT_HTTP_PORT": "8766"})
    assert config.http.enabled and config.http.host == "127.0.0.1" and config.http.port == 8766


def test_capability_lifecycle_and_bounds() -> None:
    now = [0.0]
    clients = Clients(HTTPSettings(ttl_seconds=2, max_clients=1), lambda: now[0])
    token, ref = clients.issue()
    assert token.get_secret_value() not in repr(token)
    assert token.get_secret_value() not in repr(clients._entries)
    assert clients.authenticate("Bearer " + token.get_secret_value()) is ref
    for invalid in ["", "operator", "Bearer bad", "Bearer " + "x" * 43]:
        assert clients.authenticate(invalid) is None
    with pytest.raises(ValueError):
        clients.issue()
    scope = {"type": "http"}
    request = Request(scope)
    with pytest.raises(ValueError):
        clients.resolve(request)
    clients.bind(request, ref)
    assert clients.resolve(request).connection_id == ref.identifier
    clients.revoke(uuid4())
    assert clients.resolve(request).identity.principal == "local-capability"
    clients.revoke(ref.identifier)
    with pytest.raises(ValueError):
        clients.resolve(request)
    token, ref = clients.issue()
    now[0] = 2.0
    assert clients.authenticate("Bearer " + token.get_secret_value()) is None
    clients.issue()
    now[0] = 5
    assert clients.issue()[1].identifier != ref.identifier
    clients.clear()
    assert not clients._entries
    with pytest.raises(ValueError):
        clients.resolve(None)
    now[0] = float("nan")
    with pytest.raises(ValueError):
        clients.issue()
