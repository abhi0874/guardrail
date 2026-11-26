"""Explicit environment loading without network calls or dotenv side effects."""

import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    """URL syntax validation is NOT a local-target allow-list."""

    target_url: str = "http://127.0.0.1:3000"
    log_level: str = "INFO"
    request_timeout: float = 30.0
    llm_judge_enabled: bool = False
    llm_judge_model: str | None = None

    mode: str = "sandbox"
    allowed_ports: tuple[int, ...] = (3000,)
    connection_timeout: float = 5.0

    def __post_init__(self) -> None:
        if self.mode not in {"sandbox", "http"}:
            raise ValueError("ASS_TARGET_MODE must be sandbox or http")
        if not self.allowed_ports or any(
            type(p) is not int or not 1 <= p <= 65535 for p in self.allowed_ports
        ):
            raise ValueError("ASS_ALLOWED_PORTS must contain ports in 1..65535")
        if not math.isfinite(self.connection_timeout) or self.connection_timeout <= 0:
            raise ValueError("ASS_CONNECTION_TIMEOUT must be finite and positive")
        try:
            parsed = urlsplit(self.target_url)
            port = parsed.port
            valid = (
                parsed.scheme in {"http", "https"}
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and not parsed.fragment
                and "#" not in self.target_url
                and not any(c.isspace() or ord(c) < 32 for c in self.target_url)
                and "\\" not in self.target_url
                and (port is None or port > 0)
                and not parsed.netloc.endswith(":")
            )
            if parsed.hostname:
                host = parsed.hostname
                if ":" not in host:
                    valid = valid and all(
                        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                        for label in host.rstrip(".").split(".")
                    )
        except ValueError:
            valid = False
        if not valid:
            raise ValueError(
                "ASS_TARGET_URL must be an HTTP(S) URL without credentials or fragment"
            )
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("ASS_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
        if not math.isfinite(self.request_timeout) or self.request_timeout <= 0:
            raise ValueError("ASS_REQUEST_TIMEOUT must be a finite positive number of seconds")
        if self.llm_judge_enabled and not self.llm_judge_model:
            raise ValueError("ASS_LLM_JUDGE_MODEL is required when the judge is enabled")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        """Read only supported variables; pass a mapping for isolated configuration."""
        env = os.environ if environ is None else environ
        enabled = env.get("ASS_LLM_JUDGE_ENABLED", "false").strip().lower()
        if enabled not in {"true", "false"}:
            raise ValueError("ASS_LLM_JUDGE_ENABLED must be true or false")
        try:
            timeout = float(env.get("ASS_REQUEST_TIMEOUT", "30"))
        except ValueError:
            raise ValueError(
                "ASS_REQUEST_TIMEOUT must be a finite positive number of seconds"
            ) from None
        try:
            ports = tuple(int(p) for p in env.get("ASS_ALLOWED_PORTS", "3000").split(","))
            connection_timeout = float(env.get("ASS_CONNECTION_TIMEOUT", "5"))
        except ValueError:
            raise ValueError("Invalid ASS_ALLOWED_PORTS or ASS_CONNECTION_TIMEOUT") from None
        return cls(
            mode=env.get("ASS_TARGET_MODE", "sandbox"),
            allowed_ports=ports,
            connection_timeout=connection_timeout,
            target_url=env.get("ASS_TARGET_URL", "http://127.0.0.1:3000"),
            log_level=env.get("ASS_LOG_LEVEL", "INFO").strip().upper(),
            request_timeout=timeout,
            llm_judge_enabled=enabled == "true",
            llm_judge_model=env.get("ASS_LLM_JUDGE_MODEL", "").strip() or None,
        )
