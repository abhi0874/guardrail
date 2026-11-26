"""The CLI owns stderr diagnostics. stdout belongs to the MCP transport."""

import json
import logging
import sys
from datetime import UTC, datetime

from .config import LogLevel
from .errors import ErrorCode

LOGGER = "mcp_agent_server"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            # Third-party messages can interpolate untrusted request bodies or exception details.
            "message": record.getMessage() if record.name == LOGGER else "Library diagnostic",
        }
        context: dict[str, int | str] = {}
        if getattr(record, "transport", None) == "stdio":
            context["transport"] = "stdio"
        pid = getattr(record, "process_id", None)
        if type(pid) is int and pid > 0:
            context["process_id"] = pid
        code = getattr(record, "error_code", None)
        if isinstance(code, ErrorCode):
            context["error_code"] = code.value
        if context:
            entry["context"] = context
        return json.dumps(entry, ensure_ascii=True, allow_nan=False)


class _CurrentStderr:
    """Borrow the current stderr for each operation; never own a capture stream."""

    def write(self, text: str) -> int:
        return sys.stderr.write(text)

    def flush(self) -> None:
        sys.stderr.flush()


def configure_logging(level: LogLevel) -> logging.Logger:
    logger = logging.getLogger(LOGGER)
    for old in logger.handlers[:]:
        logger.removeHandler(old)
        old.close()
    handler = logging.StreamHandler(_CurrentStderr())
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
