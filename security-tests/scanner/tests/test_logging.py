import io
import json
import logging
from datetime import datetime

import pytest
from agent_security_scanner.logging import configure_logging


@pytest.fixture(autouse=True)
def restore_logger():
    logger = logging.getLogger("agent_security_scanner")
    handlers, level, propagate = logger.handlers[:], logger.level, logger.propagate
    logger.handlers = []
    yield
    for handler in logger.handlers:
        handler.close()
    logger.handlers = handlers
    logger.setLevel(level)
    logger.propagate = propagate


def test_json_and_context(monkeypatch):
    monkeypatch.setenv("SYNTHETIC_SECRET", "must-not-appear")
    stream = io.StringIO()
    logger = configure_logging(stream=stream)
    logger.info(
        'message "quoted"\nnext',
        extra={"metadata": {"request_id": "r1", "count": 2}, "unselected": "must-not-appear"},
    )
    payload = json.loads(stream.getvalue())
    assert set(payload) == {"timestamp", "severity", "logger", "message", "metadata"}
    assert datetime.fromisoformat(payload["timestamp"]).utcoffset().total_seconds() == 0
    assert payload["severity"] == "INFO"
    assert payload["logger"] == "agent_security_scanner"
    assert payload["message"] == 'message "quoted"\nnext'
    assert payload["metadata"] == {"request_id": "r1", "count": 2}
    assert "must-not-appear" not in stream.getvalue()


def test_filtering_and_reconfiguration():
    old, stream = io.StringIO(), io.StringIO()
    root_handlers = logging.getLogger().handlers[:]
    configure_logging("DEBUG", stream=old)
    logger = configure_logging("WARNING", stream=stream)
    configure_logging("WARNING", stream=stream)
    logger.info("filtered")
    logging.getLogger("agent_security_scanner.child").warning("visible")
    assert old.getvalue() == ""
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["message"] == "visible"
    assert len(logger.handlers) == 1
    assert logging.getLogger().handlers == root_handlers


def test_invalid_level():
    with pytest.raises(ValueError, match="level"):
        configure_logging("INVALID")
