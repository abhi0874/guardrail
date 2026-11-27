"""Allowlisted process settings for the local stdio server."""

import os
import stat
from collections.abc import Mapping
from os import environ
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from .adapters.destinations import canonical_host
from .guardrails.security_settings import OutputSettings, RateSettings
from .transport.settings import HTTPSettings

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
PACKAGE = Path(__file__).resolve().parent
BUNDLED_POLICIES = PACKAGE / "_bundle/policies"
INSTALLED = BUNDLED_POLICIES.is_dir()
PROJECT = Path.home() / ".guardrail" if INSTALLED else PACKAGE.parents[1]
POLICIES = PROJECT / "policies"
DEFAULT_POLICY = (BUNDLED_POLICIES if INSTALLED else POLICIES) / "tool_access.yaml"
AUDIT_ROOT = PROJECT / ".runtime/audit"


def prepare_runtime() -> None:
    if INSTALLED:
        PROJECT.mkdir(mode=0o700, exist_ok=True)
        info = PROJECT.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Guardrail state must be a private directory owned by this user")


def audit_path(path: Path) -> Path:
    candidate = PROJECT / path
    if (
        not candidate.is_relative_to(AUDIT_ROOT)
        or ".." in path.parts
        or path.suffix != ".sqlite3"
        or (not INSTALLED and not (PROJECT / "pyproject.toml").is_file())
    ):
        raise ValueError("Use a .sqlite3 file inside Guardrail's .runtime/audit directory")
    for part in (candidate, *candidate.parents):
        if part.is_symlink():
            raise ValueError("Audit paths cannot contain symlinks")
    for suffix in ("", "-journal", "-wal", "-shm"):
        try:
            info = Path(str(candidate) + suffix).lstat()
        except FileNotFoundError:
            continue
        # Concurrent SQLite commits unlink their temporary sidecars. macOS lstat
        # can observe the regular inode after its last link has disappeared.
        # Zero links cannot alias another file; the main database must still have one.
        transient_unlinked = bool(suffix) and info.st_nlink == 0
        if not stat.S_ISREG(info.st_mode) or (info.st_nlink != 1 and not transient_unlinked):
            raise ValueError("Audit files must be regular files without links")
    return candidate


ENVIRONMENT_KEYS = {
    "MCP_AGENT_FETCH_HOSTS": "fetch_hosts",
    "MCP_AGENT_NAME": "app_name",
    "MCP_AGENT_ENVIRONMENT": "environment",
    "MCP_AGENT_LOG_LEVEL": "log_level",
    "MCP_AGENT_TRANSPORT": "transport",
    "MCP_AGENT_POLICY": "policy_file",
    "MCP_AGENT_AUDIT_DB": "audit_db",
    "MCP_AGENT_STORAGE_BACKEND": "storage_backend",
    "MCP_AGENT_DATABASE_URL": "database_url",
    "MCP_AGENT_DB_POOL_SIZE": "db_pool_size",
    "MCP_AGENT_MAX_ARGUMENT_BYTES": "max_argument_bytes",
    "MCP_AGENT_MAX_ARGUMENT_DEPTH": "max_argument_depth",
}


class Settings(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", hide_input_in_errors=True, validate_default=True
    )
    app_name: str = Field(default="mcp-agent-server", pattern=r"^[a-z][a-z0-9-]{0,63}$")
    environment: Literal["local", "test", "production"] = "local"
    log_level: LogLevel = "INFO"
    transport: Literal["stdio"] = "stdio"
    policy_file: Path = DEFAULT_POLICY
    audit_db: Path = AUDIT_ROOT / "events.sqlite3"
    storage_backend: Literal["sqlite", "postgresql"] = "sqlite"
    database_url: SecretStr | None = Field(default=None, repr=False, exclude=True)
    db_pool_size: int = Field(default=2, ge=1, le=8)
    max_argument_bytes: int = Field(default=8192, ge=2, le=1048576)
    max_argument_depth: int = Field(default=8, ge=1, le=64)

    http: HTTPSettings = Field(default_factory=HTTPSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    rate: RateSettings = Field(default_factory=RateSettings)
    fetch_hosts: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("fetch_hosts", mode="before")
    @classmethod
    def parse_hosts(cls, value: object) -> tuple[str, ...]:
        hosts = value.split(",") if isinstance(value, str) and value else value or ()
        if not isinstance(hosts, (tuple, list)) or not all(isinstance(h, str) for h in hosts):
            raise ValueError("Invalid fetch hosts")
        return tuple(canonical_host(h) for h in hosts)

    @field_validator("audit_db")
    @classmethod
    def local_path(cls, value: Path) -> Path:
        return audit_path(value)

    @model_validator(mode="after")
    def storage_configuration(self) -> "Settings":
        if self.environment == "production" and self.storage_backend != "postgresql":
            raise ValueError("Production requires explicit PostgreSQL storage")
        if self.storage_backend == "postgresql":
            from .storage.settings import connection_parameters

            connection_parameters(self.database_url, production=self.environment == "production")
        elif self.database_url is not None:
            raise ValueError("Database connection requires PostgreSQL storage")
        return self

    @classmethod
    def from_env(cls, values: Mapping[str, str] | None = None) -> "Settings":
        source = environ if values is None else values
        data: dict[str, object] = {
            field: source[key] for key, field in ENVIRONMENT_KEYS.items() if key in source
        }
        for name, model in (
            ("output", OutputSettings),
            ("rate", RateSettings),
            ("http", HTTPSettings),
        ):
            data[name] = {
                f: source[k]
                for f in model.model_fields
                if (k := f"MCP_AGENT_{name.upper()}_{f.upper()}") in source
            }
        return cls.model_validate(data)
