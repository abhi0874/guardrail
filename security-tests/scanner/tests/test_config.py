import pytest
from agent_security_scanner.config import Settings


def test_defaults():
    settings = Settings.from_env({})
    assert settings == Settings()
    assert settings.target_url == "http://127.0.0.1:3000"
    assert settings.log_level == "INFO"
    assert settings.request_timeout == 30
    assert settings.llm_judge_enabled is False
    assert settings.llm_judge_model is None


def test_environment_overrides(monkeypatch):
    values = {
        "ASS_TARGET_URL": "http://localhost:8080/chat",
        "ASS_LOG_LEVEL": "debug",
        "ASS_REQUEST_TIMEOUT": "2.5",
        "ASS_LLM_JUDGE_ENABLED": "true",
        "ASS_LLM_JUDGE_MODEL": "synthetic-test-model",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    assert Settings.from_env() == Settings(
        "http://localhost:8080/chat", "DEBUG", 2.5, True, "synthetic-test-model"
    )
    assert Settings.from_env({}) == Settings()


@pytest.mark.parametrize(
    "url",
    [
        "",
        "localhost",
        "ftp://localhost",
        "http://",
        "http://user:pass@localhost",
        "http://localhost:bad",
        "http://localhost:65536",
        "http://localhost:0",
        "http://localhost:",
        "http://local host",
        "http://localhost/#x",
        "http://[broken",
        "http://bad_host",
        "http://localhost\\evil",
        "http://\nlocalhost",
    ],
)
def test_invalid_url(url):
    with pytest.raises(ValueError, match="ASS_TARGET_URL"):
        Settings.from_env({"ASS_TARGET_URL": url})


@pytest.mark.parametrize("timeout", ["0", "-1", "nan", "inf", "-inf", "abc", ""])
def test_invalid_timeout(timeout):
    with pytest.raises(ValueError, match="ASS_REQUEST_TIMEOUT"):
        Settings.from_env({"ASS_REQUEST_TIMEOUT": timeout})


@pytest.mark.parametrize(
    "env, message",
    [
        ({"ASS_LOG_LEVEL": "TRACE"}, "ASS_LOG_LEVEL"),
        ({"ASS_LLM_JUDGE_ENABLED": "yes"}, "ASS_LLM_JUDGE_ENABLED"),
        ({"ASS_LLM_JUDGE_ENABLED": "true"}, "ASS_LLM_JUDGE_MODEL"),
    ],
)
def test_invalid_options(env, message):
    with pytest.raises(ValueError, match=message):
        Settings.from_env(env)


def test_url_validation_is_not_allowlist():
    assert Settings(target_url="https://example.com/chat").target_url == "https://example.com/chat"
    assert Settings(target_url="http://[::1]:3000").target_url == "http://[::1]:3000"
