from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.config import Settings


def create_store(settings: Settings) -> AuditStore:
    if settings.storage_backend == "postgresql":
        from .postgres import PostgresStore

        return PostgresStore(settings)
    return AuditStore(settings.audit_db)
