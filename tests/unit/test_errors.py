import json

import pytest

from mcp_agent_server import server
from mcp_agent_server.config import Settings
from mcp_agent_server.errors import ApplicationError, ConfigurationError, InternalError


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ConfigurationError(), "invalid_configuration"),
        (InternalError(), "internal_error"),
    ],
)
def test_public_errors_have_fixed_safe_payloads(error: ApplicationError, code: str) -> None:
    public = error.public.model_dump(mode="json")
    assert public == {"code": code, "message": str(error), "retryable": False}
    assert "/" not in str(error) and "Traceback" not in str(error)


def test_internal_startup_error_hides_cause(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(settings: Settings) -> None:
        raise RuntimeError("private failure at /private/secret")

    monkeypatch.setattr(server, "create_server", fail)
    assert server.main() == 1
    out, err = capsys.readouterr()
    assert not out and "private failure" not in err and "Traceback" not in err
    assert json.loads(err)["context"]["error_code"] == "internal_error"
