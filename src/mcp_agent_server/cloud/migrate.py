"""Separate operator migration command; never a web startup action."""

import os
import sys

from pydantic import SecretStr

from mcp_agent_server.storage.migrate import migrate
from mcp_agent_server.storage.settings import connection_parameters

from .storage import migrate_cloud


def main() -> int:
    try:
        raw = os.environ.get("MCP_AGENT_MIGRATION_URL")
        parameters = connection_parameters(SecretStr(raw) if raw else None, production=True)
        migrate(
            parameters,
            lock_seconds=float(os.environ.get("MCP_AGENT_MIGRATION_LOCK_SECONDS", "2")),
            statement_seconds=float(os.environ.get("MCP_AGENT_MIGRATION_STATEMENT_SECONDS", "5")),
        )
        migrate_cloud(
            parameters,
            lock_seconds=float(os.environ.get("MCP_AGENT_MIGRATION_LOCK_SECONDS", "2")),
            statement_seconds=float(os.environ.get("MCP_AGENT_MIGRATION_STATEMENT_SECONDS", "5")),
        )
    except Exception:
        print("Cloud migration failed; inspect configuration privately.", file=sys.stderr)
        return 1
    print("Cloud schemas migrated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
