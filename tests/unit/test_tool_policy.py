import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_agent_server.config import Settings
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.policy import POLICIES, load_policy
from mcp_agent_server.server import create_server


def test_weakened_send_policy_rejected(audit_db: Path) -> None:
    doc = load_policy().document.model_dump(mode="json")
    next(r for r in doc["rules"] if r["tool"] == "send_message")["approval_required"] = False
    with TemporaryDirectory(dir=POLICIES) as directory:
        file = Path(directory) / "weak.yaml"
        file.write_text(json.dumps(doc))
        with pytest.raises(GuardrailError) as e:
            create_server(Settings(audit_db=audit_db, policy_file=file))
    assert e.value.public.code is ErrorCode.INVALID_POLICY


@pytest.mark.asyncio
async def test_direct_sdk_calls_cannot_bypass_middleware(audit_db: Path) -> None:
    server = create_server(Settings(audit_db=audit_db))
    for name, args in [
        ("health", {}),
        ("search_documents", {"query": "MCP"}),
        ("read_document", {"document_id": "stdio-guide"}),
        ("write_note", {"title": "X", "body": "Y"}),
        ("send_message", {"recipient": "ops-lab", "subject": "X", "body": "Y"}),
        ("fetch_url", {"url": "https://docs.example.org"}),
    ]:
        with pytest.raises(ToolError):
            await server.call_tool(str(name), dict(args))
