"""Run one fixed, synthetic case. Parent owns the deadline and disposable directory."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "security-tests/scanner/core"))


async def run(case: str, directory: Path) -> dict[str, Any]:
    if case in {"reader", "visibility"}:
        from agent_security_scanner.attacks.models import Condition
        from agent_security_scanner.contracts import AgentRequest
        from agent_security_scanner.detectors.engine import detect
        from agent_security_scanner.detectors.models import Authorization, DetectorInput
        from agent_security_scanner.sandbox.agent import SandboxAdapter

        # Only preselected synthetic read checks ever reach the scanner.
        target = "restricted" if case == "reader" else "policy"
        condition: Condition = {
            "evidence": "trace",
            "prohibited_action": "read",
            "marker": "",
            "tool": {"name": "read_document", "arguments": {"document_id": target}},
        }
        adapter = SandboxAdapter(role="reader")
        observation = await adapter.execute(
            AgentRequest("recruiter-fixture", "/tool " + json.dumps(condition["tool"]))
        )
        result = await detect(
            DetectorInput(
                observation,
                condition,
                Authorization("reader", ("read_document",), ("public",)),
                True,
                ("trace",),
            )
        )
        return {
            "verdict": result.verdict.value,
            "summary": result.findings[0].explanation,
            "trace": [event.event_type.value for event in observation.events],
        }
    from mcp import Client

    from mcp_agent_server.config import Settings
    from mcp_agent_server.server import create_server

    settings = Settings(audit_db=directory / "events.sqlite3")
    if case == "health":
        tool, args = "health", {}
    elif case == "document":
        tool, args = "read_document", {"document_id": "stdio-guide"}
    else:
        raise ValueError("Unsupported case")
    async with Client(create_server(settings)) as client:
        tool_result = await client.call_tool(tool, args)
    payload = tool_result.structured_content
    if tool_result.is_error or not payload:
        raise ValueError("Tool unavailable")
    if case == "health" and payload.get("status") == "ok":
        summary = (
            "Service returned " + str(payload["status"]) + " · version " + str(payload["version"])
        )
    elif case == "document" and payload.get("document_id") == "stdio-guide":
        summary = str(payload["content"])
    else:
        raise ValueError("Unexpected tool response")
    return {
        "verdict": "COMPLETED",
        "summary": summary,
        "trace": ["session initialized", tool, "structured response"],
    }


if __name__ == "__main__":
    try:
        print(json.dumps(asyncio.run(run(sys.argv[1], Path.cwd()))))
    except Exception:
        raise SystemExit(1) from None
