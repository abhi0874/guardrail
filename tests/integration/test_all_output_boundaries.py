"""All six registered tools must return safe provenance through the SDK."""

from pathlib import Path

import pytest

from mcp_agent_server.tools.models import Message
from mcp_agent_server.tools.registry import SPECS

from .audit_support import connected
from .test_production_tools import BOOT, key, operator


@pytest.mark.asyncio
async def test_every_production_tool_has_output_boundary(audit_db: Path) -> None:
    async with connected(
        audit_db, bootstrap=BOOT, limits={"MCP_AGENT_FETCH_HOSTS": "docs.example.org"}
    ) as client:
        msg = Message(recipient="ops-lab", subject="Metadata", body="Synthetic")
        calls: list[tuple[str, dict[str, object]]] = [
            ("health", {}),
            ("search_documents", {"query": "approval"}),
            ("read_document", {"document_id": "approval-guide"}),
            ("write_note", {"title": "Metadata", "body": "Synthetic"}),
            ("send_message", msg.model_dump()),
            ("fetch_url", {"url": "https://docs.example.org/"}),
        ]
        observed: list[str] = []
        for name, args in calls:
            if name == "send_message":
                operator(audit_db, msg)
            result = await client.call_tool(name, args, meta=key(name))
            assert result.structured_content and result.meta
            SPECS[name].result.model_validate(result.structured_content, strict=True)
            report = result.meta["mcp-agent-server/output"]
            assert report == {
                "source": name,
                "profile": "v1",
                "disposition": "allow",
                "rules": [],
                "redactions": 0,
            }
            observed.append(name)
        assert set(observed) == set(SPECS)
        print("output_boundary_verified", observed)


def test_production_factories_share_global_limiter(audit_db: Path) -> None:
    from mcp_agent_server.config import Settings
    from mcp_agent_server.guardrails.middleware import ToolMiddleware
    from mcp_agent_server.server import create_server

    first = create_server(Settings(audit_db=audit_db))
    second = create_server(Settings(audit_db=audit_db))
    a = next(m for m in first.middleware if isinstance(m, ToolMiddleware))
    b = next(m for m in second.middleware if isinstance(m, ToolMiddleware))
    assert a.connection_id != b.connection_id
    assert a.pipeline.limiter is b.pipeline.limiter
    print("production_server_instances=2 distinct_connections=True shared_global_bucket=True")
