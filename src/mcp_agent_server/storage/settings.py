"""Validate secrets without echoing libpq parse errors or accepting implicit hosts."""

from psycopg.conninfo import conninfo_to_dict
from pydantic import SecretStr


def connection_parameters(secret: SecretStr | None, *, production: bool) -> dict[str, str]:
    try:
        if secret is None or len(secret.get_secret_value()) > 8192:
            raise ValueError
        raw = secret.get_secret_value()
        if not raw.startswith(("postgresql://", "postgres://")):
            raise ValueError
        values = {k: str(v) for k, v in conninfo_to_dict(raw).items() if v is not None}
        allowed = {"host", "port", "user", "password", "dbname", "sslmode", "sslrootcert"}
        if not values.keys() <= allowed or not all(
            values.get(k) for k in ("host", "user", "password", "dbname")
        ):
            raise ValueError
        host = values["host"]
        if any(c in host for c in ",/\\ ") or any(c.isspace() for c in host) or not host.isascii():
            raise ValueError
        if not 1 <= int(values.get("port", "5432")) <= 65535:
            raise ValueError
        local = host in ("127.0.0.1", "::1", "localhost")
        mode = values.get("sslmode", "verify-full")
        if mode != "verify-full" and not (not production and local and mode == "disable"):
            raise ValueError
        if production and local:
            raise ValueError
        values["port"] = values.get("port", "5432")
        values["options"] = ""
        values["sslrootcert"] = values.get("sslrootcert", "system" if mode == "verify-full" else "")
        values["sslmode"] = mode
        # Never inherit libpq connect_timeout, service, options or target selection.
        values["connect_timeout"] = "2"
        values["application_name"] = "mcp-agent-server"
        return values
    except Exception:
        raise ValueError("Explicit, secure PostgreSQL connection required") from None
