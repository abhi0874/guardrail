"""Hand-crafted adversarial RPCs against real HTTP and subprocess stdio servers."""

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from integration.audit_support import connected, rows
from integration.http_support import client, listener
from integration.test_production_tools import BOOT, key
from mcp import MCPError, types
from pydantic import TypeAdapter

from mcp_agent_server.adapters.outbox import Outbox
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.policy import load_policy
from mcp_agent_server.tools.models import Message

from .test_http_security import body, headers

MARKER = "STEP10_PRIVATE_PROTOCOL_SENTINEL"
KEY = "mcp-agent-server/idempotency-key"


def effects(db: Path) -> tuple[int, int, int]:
    with AuditStore(db).transaction() as conn:
        notes, operations, consumed = conn.execute(
            "select (select count(*) from notes), (select count(*) from operations), "
            "(select count(consumed_event) from approvals)"
        ).fetchone()
    return notes, operations, consumed


@pytest.mark.asyncio
async def test_grant_laundering_and_receipt_theft(audit_db: Path) -> None:
    box = Outbox()
    msg = Message(recipient="docs-lab", subject="Receipt check", body="Approved synthetic text")
    async with listener(audit_db, outbox=box) as (url, registry, _):
        a, owner = registry.issue()
        b, stranger = registry.issue()
        gate = ApprovalGate(AuditStore(audit_db), load_policy())
        grant = gate.issue(
            owner.authorization, "send_message", msg, issuer="fixture", ttl_seconds=60
        )
        stolen = TypeAdapter(types.RequestParamsMeta).validate_python(
            {
                KEY: "owner-key",
                "principal": "operator",
                "roles": ["admin"],
                "connection_id": str(owner.identifier),
                "approval_token": grant.get_secret_value(),
                "mcp-agent-server/trusted-client": {"identifier": str(owner.identifier)},
            }
        )
        async with client(url, a) as ca, client(url, b) as cb:
            for caller, data in (
                (cb, msg.model_dump()),
                (ca, {**msg.model_dump(), "body": MARKER}),
            ):
                with pytest.raises(MCPError) as denied:
                    await caller.call_tool("send_message", data, meta=stolen)
                assert denied.value.data["code"] == "approval_required"
                assert MARKER not in str(denied.value)
                assert grant.get_secret_value() not in str(denied.value)
                assert effects(audit_db) == (0, 0, 0) and not box.entries
            receipt = await ca.call_tool("send_message", msg.model_dump(), meta=key("owner-key"))
            assert receipt.structured_content and receipt.structured_content["recorded_in_memory"]
            receipt_id = receipt.structured_content["simulation_id"]
            assert len(box.entries) == 1
            assert box.entries[0][1] == msg and box.entries[0][0].simulation_id == receipt_id
            for caller, tool, arguments, op, code in [
                (cb, "send_message", msg.model_dump(), "owner-key", "idempotency_key_conflict"),
                (
                    ca,
                    "write_note",
                    {"title": "Receipt", "body": "synthetic"},
                    "owner-key",
                    "idempotency_key_conflict",
                ),
                (ca, "send_message", msg.model_dump(), "other-key", "approval_consumed"),
            ]:
                with pytest.raises(MCPError) as denial:
                    await caller.call_tool(tool, arguments, meta=key(op))
                assert denial.value.data["code"] == code
                assert receipt_id not in str(denial.value) and "receipt" not in denial.value.data
            first = rows(audit_db)[0]
            assert first["connection_id"] == str(stranger.identifier)
            with gate.store.transaction() as conn:
                assert (
                    conn.execute(
                        "select principal from audit_policy where event_id=?", (first["event_id"],)
                    ).fetchone()[0]
                    == "local-capability"
                )
            retry = await ca.call_tool("send_message", msg.model_dump(), meta=key("owner-key"))
            assert retry.meta and retry.meta["mcp-agent-server/replayed"] is True
            assert retry.structured_content == receipt.structured_content
            assert effects(audit_db) == (0, 1, 1) and len(box.entries) == 1
    disk = audit_db.read_bytes()
    for value in (grant.get_secret_value(), a.get_secret_value(), b.get_secret_value(), MARKER):
        assert value.encode() not in disk


@pytest.mark.asyncio
async def test_stdio_names_and_key_type_confusion(audit_db: Path) -> None:
    async with connected(audit_db, bootstrap=BOOT) as peer:
        for name in ("send_message/../write_note", "write_ｎote", "operator.issue_approval"):
            with pytest.raises(MCPError) as denied:
                await peer.call_tool(name, {"title": "Bypass", "body": MARKER}, meta=key("shared"))
            assert denied.value.data["code"] == "unknown_tool"
            assert rows(audit_db)[-1]["tool_name"] == "<unknown>"
        for invalid in (True, {"value": "shared"}, "shared\u0000suffix", "ｅxample"):
            with pytest.raises(MCPError) as denied:
                await peer.call_tool(
                    "write_note",
                    {"title": "Bypass", "body": MARKER},
                    meta=TypeAdapter(types.RequestParamsMeta).validate_python({KEY: invalid}),
                )
            assert denied.value.data["code"] == "invalid_idempotency_key"
        assert effects(audit_db) == (0, 0, 0)
        assert (audit_db.parent / "outbox-count").read_text() == "0"
        assert MARKER.encode() not in audit_db.read_bytes()
        ok = await peer.call_tool(
            "write_note", {"title": "Control", "body": "Synthetic"}, meta=key("shared")
        )
        assert ok.structured_content and ok.structured_content["persisted"] is True
        assert effects(audit_db) == (1, 1, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["origin", "authorization", "mcp-protocol-version", "host"])
async def test_ambiguous_authority_headers(audit_db: Path, header: str) -> None:
    async with listener(audit_db) as (url, registry, _):
        token, _ = registry.issue()
        authority = url.split("/")[2]
        base = {
            **headers(token.get_secret_value(), name="write_note"),
            "host": authority,
            "origin": "http://" + authority,
        }
        good = base.pop(header)
        bad = {
            "origin": "http://evil.invalid",
            "authorization": "Bearer " + MARKER,
            "mcp-protocol-version": "2025-03-26",
            "host": "evil.invalid",
        }[header]
        packet = mutation()
        async with httpx.AsyncClient(trust_env=False) as raw:
            for values in [(good, bad), (bad, good)]:
                # HTTPX rejects duplicate Host locally; raw TCP reaches the server parser.
                payload = json.dumps(packet).encode()
                fields = [
                    *base.items(),
                    (header, values[0]),
                    (header, values[1]),
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(payload))),
                    ("Connection", "close"),
                ]
                wire = (
                    "POST /mcp HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields) + "\r\n"
                )
                async with asyncio.timeout(3):
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", int(authority.split(":")[1])
                    )
                    try:
                        writer.write(wire.encode("ascii") + payload)
                        await writer.drain()
                        reply = await reader.read()
                    finally:
                        writer.close()
                        await writer.wait_closed()
                assert reply.split(b" ", 2)[1] == b"400"
                assert (
                    MARKER.encode() not in reply and token.get_secret_value().encode() not in reply
                )
                assert not rows(audit_db) and effects(audit_db) == (0, 0, 0)
            response = await raw.post(url, headers={**base, header: good}, json=packet)
            assert response.json()["result"]["structuredContent"]["persisted"] is True
            assert effects(audit_db) == (1, 1, 0)


def mutation() -> dict[str, Any]:
    data: dict[str, Any] = body(name="write_note")
    data["params"]["arguments"] = {"title": "Wire", "body": "Synthetic"}
    data["params"]["_meta"][KEY] = "same-key"
    return data


@pytest.mark.asyncio
async def test_malformed_streams_cannot_claim_write_key(audit_db: Path) -> None:
    async with listener(audit_db) as (url, registry, cfg):
        token, _ = registry.issue()
        h = {
            **headers(token.get_secret_value(), name="write_note"),
            "content-type": "application/json",
        }
        valid = json.dumps(mutation()).encode()

        async def chunked() -> AsyncIterator[bytes]:
            # The first chunk looks complete. The rest exceeds the limit, with no Content-Length.
            yield valid
            yield b" " * cfg.http.max_body_bytes

        async with httpx.AsyncClient(trust_env=False) as raw:
            oversized = await raw.post(url, headers=h, content=chunked())
            assert oversized.status_code == 413 and not rows(audit_db)
            for wire in (
                valid + b"{}",
                valid[:-2],
                valid.replace(b'"Synthetic"', b"NaN"),
                valid.replace(b'"Synthetic"', b'{"$ref":"' + MARKER.encode() + b'"}'),
            ):
                response = await raw.post(url, headers=h, content=wire)
                assert "error" in response.json() and "result" not in response.json()
                assert MARKER not in response.text and token.get_secret_value() not in response.text
                assert effects(audit_db) == (0, 0, 0)
            control = await raw.post(url, headers=h, content=valid)
            assert control.json()["result"]["structuredContent"]["persisted"] is True
            assert effects(audit_db) == (1, 1, 0)
