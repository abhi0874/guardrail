import pytest
from pydantic import ValidationError

from mcp_agent_server.config import Settings


def test_defaults_and_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    assert Settings.from_env({}) == Settings()
    values = {
        "MCP_AGENT_NAME": "lab-health",
        "MCP_AGENT_ENVIRONMENT": "test",
        "MCP_AGENT_LOG_LEVEL": "DEBUG",
        "MCP_AGENT_TRANSPORT": "stdio",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    assert Settings.from_env() == Settings(
        app_name="lab-health", environment="test", log_level="DEBUG"
    )
    assert Settings.from_env({"OLLAMA_MODEL": "irrelevant"}) == Settings()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("MCP_AGENT_NAME", ""),
        ("MCP_AGENT_NAME", "name\nspoof"),
        ("MCP_AGENT_ENVIRONMENT", "unknown"),
        ("MCP_AGENT_LOG_LEVEL", "TRACE"),
        ("MCP_AGENT_TRANSPORT", "streamable-http"),
    ],
)
def test_validation_identifies_field(key: str, value: str) -> None:
    with pytest.raises(ValidationError) as failure:
        Settings.from_env({key: value})
    assert failure.value.errors(include_input=False)[0]["loc"]


def test_invalid_environment_value_is_not_disclosed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mcp_agent_server.server import main

    monkeypatch.setenv("MCP_AGENT_NAME", "sensitive/rejected/value")
    assert main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "app_name" in captured.err
    assert "invalid_configuration" in captured.err
    assert "sensitive/rejected/value" not in captured.err
