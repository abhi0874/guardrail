import asyncio
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

import pytest
from mcp import MCPError, types
from pydantic import TypeAdapter

from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.authorization import LOCAL, AuthorizationContext
from mcp_agent_server.guardrails.policy import POLICIES, load_policy
from mcp_agent_server.guardrails.validation import HealthArguments

from .audit_support import connected, rows


@pytest.mark.asyncio
async def test_health_uses_policy_and_ignores_client_claims(audit_db: Path) -> None:
    policy = load_policy()
    async with connected(audit_db) as client:
        assert sorted(t.name for t in (await client.list_tools()).tools) == [
            "fetch_url",
            "health",
            "read_document",
            "search_documents",
            "send_message",
            "write_note",
        ]
        with pytest.raises(MCPError) as failure:
            await client.call_tool("health", {"role": "admin", "approved": True, "is_admin": True})
        assert failure.value.data["code"] == "invalid_tool_arguments"
        assert not (await client.call_tool("health")).is_error
    with closing(sqlite3.connect(audit_db)) as db:
        metadata = db.execute("SELECT policy_digest,principal FROM audit_policy").fetchall()
        assert metadata == [(policy.digest, LOCAL.principal)] * 3
    print(
        f"discovery=health events=denied,pre,post principal={LOCAL.principal} "
        f"policy={policy.digest}"
    )


@pytest.mark.asyncio
async def test_operator_grant_through_real_stdio_without_bearer(audit_db: Path) -> None:
    doc = load_policy().document.model_dump(mode="json")
    doc["rules"][0]["approval_required"] = True
    with TemporaryDirectory(dir=POLICIES) as tmp:
        path = Path(tmp) / "gated.yaml"
        path.write_text(json.dumps(doc))
        config = {"MCP_AGENT_POLICY": str(path)}
        async with connected(audit_db, limits=config) as client:
            assert sorted(t.name for t in (await client.list_tools()).tools) == [
                "fetch_url",
                "health",
                "read_document",
                "search_documents",
                "send_message",
                "write_note",
            ]
            with pytest.raises(MCPError) as failure:
                await client.call_tool("health")
            assert failure.value.data["code"] == "approval_required"
            connection = UUID(rows(audit_db)[-1]["connection_id"])
            gate = ApprovalGate(AuditStore(audit_db), load_policy(path))
            ctx = AuthorizationContext(identity=LOCAL, connection_id=connection)
            secret = gate.issue(
                ctx, "health", HealthArguments(), issuer="test-operator", ttl_seconds=60
            )
            success = await client.call_tool("health", {})
            assert success.structured_content and success.structured_content["status"] == "ok"
            with pytest.raises(MCPError) as replay:
                await client.call_tool("health", {})
            assert replay.value.data["code"] == "approval_consumed"
            gate.issue(ctx, "health", HealthArguments(), issuer="test-operator", ttl_seconds=60)
        async with connected(audit_db, limits=config) as restarted:
            with pytest.raises(MCPError) as fresh:
                await restarted.call_tool("health")
            assert fresh.value.data["code"] == "approval_required"
        assert secret.get_secret_value() not in (audit_db.parent / "stderr.jsonl").read_text()
    print(
        "real stdio: required -> operator grant -> success -> consumed; new connection -> required"
    )


@pytest.mark.asyncio
async def test_explicit_policy_deny_health(audit_db: Path) -> None:
    doc = load_policy().document.model_dump(mode="json")
    doc["rules"][0]["action"] = "deny"
    with TemporaryDirectory(dir=POLICIES) as tmp:
        path = Path(tmp) / "deny.yaml"
        path.write_text(json.dumps(doc))
        async with connected(audit_db, limits={"MCP_AGENT_POLICY": str(path)}) as client:
            with pytest.raises(MCPError) as failure:
                await client.call_tool("health")
            assert failure.value.data["code"] == "policy_denied"
    assert [r["phase"] for r in rows(audit_db)] == ["denied"]


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", [True, False])
async def test_invalid_configured_policy_stops_startup(audit_db: Path, missing: bool) -> None:
    with TemporaryDirectory(dir=POLICIES) as tmp:
        path = Path(tmp) / "bad.yaml"
        if not missing:
            path.write_text("default_action: permit\nrules: []")
        async with asyncio.timeout(10):
            child = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "mcp_agent_server",
                env={"MCP_AGENT_POLICY": str(path), "MCP_AGENT_AUDIT_DB": str(audit_db)},
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=audit_db.parent,
            )
            out, err = await child.communicate()
        assert child.returncode == 1 and not out and not audit_db.exists()
        assert json.loads(err)["context"]["error_code"] == "invalid_policy"
        print(f"startup exit={child.returncode} stdout_bytes={len(out)} code=invalid_policy")


@pytest.mark.asyncio
async def test_peer_metadata_cannot_elevate_identity(audit_db: Path) -> None:
    doc = load_policy().document.model_dump(mode="json")
    doc["rules"][0]["roles"] = ["admin"]
    with TemporaryDirectory(dir=POLICIES) as tmp:
        path = Path(tmp) / "admin.yaml"
        path.write_text(json.dumps(doc))
        async with connected(audit_db, limits={"MCP_AGENT_POLICY": str(path)}) as client:
            with pytest.raises(MCPError) as failure:
                await client.call_tool(
                    "health",
                    {},
                    meta=TypeAdapter(types.RequestParamsMeta).validate_python(
                        {"role": "admin", "is_admin": True, "approved": True}
                    ),
                )
    assert failure.value.data["code"] == "principal_not_permitted"
    assert rows(audit_db)[0]["phase"] == "denied"
