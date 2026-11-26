"""JSON logging scoped to this package; only explicit metadata is emitted."""

import json
import logging
from datetime import UTC, datetime
from typing import TextIO


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "severity": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        metadata = getattr(record, "metadata", None)
        if metadata is not None:
            payload["metadata"] = metadata
        return json.dumps(payload, ensure_ascii=False, allow_nan=False)


def configure_logging(level: str = "INFO", *, stream: TextIO | None = None) -> logging.Logger:
    """Configure the package logger idempotently; leave the root logger untouched.

    Call during application startup. Metadata must be JSON-serializable. Callers
    must not include credentials in messages or metadata; environment variables,
    arbitrary record extras and exception locals are never collected.
    """
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("Invalid logging level")
    logger = logging.getLogger("agent_security_scanner")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
