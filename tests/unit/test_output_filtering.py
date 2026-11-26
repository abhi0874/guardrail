import pytest
from pydantic import SecretStr, ValidationError

from mcp_agent_server.config import Settings
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.output_filtering import OutputGuard
from mcp_agent_server.guardrails.security_settings import OutputSettings
from mcp_agent_server.tools.models import Document, NoteReceipt

CANARY = "SYNTHETIC_" + "OUTPUT_CANARY_731"
CREDENTIAL = "sk-" + "s" * 24


def guard(**options: object) -> OutputGuard:
    return OutputGuard(
        OutputSettings.model_validate({"literals": [CANARY], "max_text": 1024, **options})
    )


def test_nested_masks_and_counts() -> None:
    output, report = guard().process(
        {"content": [CANARY, {"text": CREDENTIAL + " " + CANARY}]}, "resource"
    )
    assert CANARY not in str(output) and CREDENTIAL not in str(output)
    assert report.masks == 3 and report.rules == {"literal", "provider-key"}
    assert output == {"content": ["[REDACTED]", {"text": "[REDACTED] [REDACTED]"}]}
    assert guard().process(output, "resource")[0] == output


def test_sensitive_keys_and_identifiers_fail() -> None:
    for payload in [{CANARY: "data"}, {"document_id": CANARY}]:
        with pytest.raises(GuardrailError) as e:
            guard().process(payload, "read_document", tool=True)
        assert e.value.public.code is ErrorCode.OUTPUT_UNSAFE


@pytest.mark.parametrize(
    "payload", [{1: "x"}, {"x": object()}, {"x": float("nan")}, {"x": "\ud800"}, 2**100]
)
def test_malformed_values_fail_safely(payload: object) -> None:
    with pytest.raises(GuardrailError):
        guard().process(payload, "resource")


@pytest.mark.parametrize(
    "settings,payload",
    [
        ({"max_text": 128}, "x" * 129),
        ({"max_depth": 3}, {"a": {"b": {"c": [1]}}}),
        ({"max_items": 16}, list(range(17))),
        ({"max_bytes": 512}, ["a" * 100] * 6),
        ({"max_text": 128}, "é" * 65),
    ],
)
def test_output_bounds(settings: dict[str, object], payload: object) -> None:
    with pytest.raises(GuardrailError) as e:
        guard(**settings).process(payload, "resource")
    assert e.value.public.code is ErrorCode.OUTPUT_LIMIT


@pytest.mark.parametrize(
    "options",
    [
        {"profile": "unknown"},
        {"patterns": ["bearer"] * 4},
        {"literals": ["secret"] * 33},
        {"patterns": " " * 32769},
        {"patterns": ["(a+)+$"]},
        {"literals": [""]},
        {"literals": ["abc"]},
        {"literals": ["REDACTED"]},
        {"max_bytes": -1},
        {"max_items": 100000},
        {"max_depth": 100},
        {"literals": ["x" * 257]},
        {"patterns": "["},
        {"max_text": float("inf")},
    ],
)
def test_invalid_configuration(options: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        OutputSettings.model_validate(options)


def test_secret_config_is_hidden() -> None:
    settings = Settings.from_env({"MCP_AGENT_OUTPUT_LITERALS": '["' + CANARY + '"]'})
    assert CANARY not in repr(settings) and CANARY not in settings.model_dump_json()
    assert settings.output.literals == (SecretStr(CANARY),)


def test_schema_and_final_wire_size() -> None:
    output = OutputGuard(OutputSettings(), {"write_note": NoteReceipt})
    with pytest.raises(GuardrailError):
        output.render("write_note", {"note_id": "bad", "persisted": True}, False, None, True)
    tiny = OutputGuard(OutputSettings(max_bytes=512))
    with pytest.raises(GuardrailError) as e:
        tiny.render("resource", {"text": "a" * 300}, None, None, True)
    assert e.value.public.code is ErrorCode.OUTPUT_LIMIT


def test_resource_and_document_contracts() -> None:
    g = OutputGuard(OutputSettings(literals=(SecretStr(CANARY),)), {"read_document": Document})
    data = {"document_id": "stdio-guide", "title": "Guide", "category": "test", "content": CANARY}
    r = g.render("read_document", data, None, None, True)
    cleaned = Document.model_validate(r["structuredContent"], strict=True)
    assert cleaned.content == "[REDACTED]"
    resource = {"contents": [{"uri": "fixture://guide", "text": "Training: " + CANARY}]}
    result, report = g.process(resource, "resource", tool=True)
    assert CANARY not in str(result) and report.masks == 1


def test_overlap_and_pattern_credentials() -> None:
    g = OutputGuard(OutputSettings(literals=(SecretStr("aaaa"), SecretStr("aaaaa"))))
    assert g.process("aaaaaa", "resource")[0] == "[REDACTED]"
    aws = "AKIA" + "A" * 16
    value = "Bearer " + "x" * 20
    result, r = guard().process([aws, value, "normal long identifier 0123456789abcdef"], "resource")
    assert result == ["[REDACTED]", "[REDACTED]", "normal long identifier 0123456789abcdef"]
    assert r.rules == {"aws-key", "bearer"}


def test_error_messages_and_filter_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    g = guard()
    assert g.error_message("Failure " + CANARY) == "Failure [REDACTED]"

    def broken(text: str, source: str) -> None:
        raise RuntimeError(CANARY)

    monkeypatch.setattr("mcp_agent_server.guardrails.output_filtering.screen", broken)
    with pytest.raises(GuardrailError) as e:
        g.process({"text": CANARY}, "resource")
    assert CANARY not in str(e.value)
    assert g.error_message(CANARY) == ""


def test_empty_output_and_expansion_bounds() -> None:
    empty_values: list[object] = [None, "", [], {}]
    for empty in empty_values:
        assert guard().process(empty, "resource")[0] == empty
    g = guard(literals=["aaaa"], max_text=128)
    with pytest.raises(GuardrailError) as err:
        g.process("aaaa " * 25, "resource")
    assert err.value.public.code is ErrorCode.OUTPUT_LIMIT


def test_raw_metadata_and_text_are_rebuilt_from_safe_structured_data() -> None:
    g = guard()
    rendered = g.render("fixture", {"text": CANARY}, None, None, False)
    assert rendered["content"] == [{"type": "text", "text": '{"text":"[REDACTED]"}'}]
    assert CANARY not in str(rendered)
