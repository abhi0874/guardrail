import json
import logging
from datetime import datetime, timedelta

import pytest

from mcp_agent_server.logging import JsonFormatter, configure_logging


def test_stderr_json_level_and_reconfiguration(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("DEBUG")
    logger = configure_logging("WARNING")
    logger.info("filtered")
    logger.warning("probe", extra={"transport": "stdio", "private_value": "unpublished"})
    out, err = capsys.readouterr()
    assert not out and len(err.splitlines()) == 1
    record = json.loads(err)
    assert record["level"] == "WARNING"
    assert record["logger"] == "mcp_agent_server"
    assert record["message"] == "probe"
    assert record["context"] == {"transport": "stdio"}
    assert datetime.fromisoformat(record["timestamp"]).utcoffset() == timedelta(0)
    assert "unpublished" not in err


def test_library_exception_details_are_private() -> None:
    record = logging.LogRecord("mcp.library", logging.ERROR, __file__, 1, "private body", (), None)
    output = JsonFormatter().format(record)
    assert json.loads(output)["message"] == "Library diagnostic"
    assert "private body" not in output and __file__ not in output


def test_closed_capture_is_not_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    first, second = io.StringIO(), io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr("sys.stderr", first)
        logger = configure_logging("WARNING")
        logger.warning("first")
        first.close()
        patch.setattr("sys.stderr", second)
        logger.warning("second", extra={"private_value": "synthetic-private"})
        handler = logger.handlers[0]
        handler.flush()
        handler.close()
        handler.close()
        assert not second.closed
        logger = configure_logging("WARNING")
        logger.warning("third")
        assert len(logger.handlers) == 1
    records = [json.loads(line) for line in second.getvalue().splitlines()]
    assert [r["message"] for r in records] == ["second", "third"]
    assert "synthetic-private" not in second.getvalue()


@pytest.mark.asyncio
async def test_denial_after_closed_capture_emits_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    from pydantic import BaseModel

    from mcp_agent_server.guardrails.pipeline import Pipeline
    from mcp_agent_server.guardrails.validation import HealthArguments

    from .test_guardrail_pipeline import Recorder, request

    previous = io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr("sys.stderr", previous)
        configure_logging("WARNING")
    previous.close()
    pipe = Pipeline(Recorder(), {"health": HealthArguments}, 100, 2)

    async def unreachable(_: BaseModel) -> None:
        raise AssertionError("Denied handler ran")

    execution, result = await pipe.execute(request("private-unknown"), unreachable)
    assert execution.error and result is None
    out, err = capsys.readouterr()
    assert out == ""
    records = [json.loads(line) for line in err.splitlines()]
    assert len(records) == 1
    assert records[0]["context"]["error_code"] == "unknown_tool"
    assert "private-unknown" not in err


def test_real_stream_failure_is_not_suppressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io

    closed = io.StringIO()
    closed.close()
    with monkeypatch.context() as patch:
        patch.setattr("sys.stderr", closed)
        logger = configure_logging("WARNING")
        handler = logger.handlers[0]
        assert isinstance(handler, logging.StreamHandler)
        with pytest.raises(ValueError):
            handler.stream.write("probe")
    assert logging.raiseExceptions is True
