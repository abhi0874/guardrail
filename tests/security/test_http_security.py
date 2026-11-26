import asyncio
from pathlib import Path

import httpx
import pytest
from integration.http_support import listener
from mcp_types import CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY

from mcp_agent_server.audit.storage import AuditStore

VERSION = "2026-07-28"


def body(method: str = "tools/call", name: str = "health") -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            "name": name,
            "arguments": {},
            "_meta": {PROTOCOL_VERSION_META_KEY: VERSION, CLIENT_CAPABILITIES_META_KEY: {}},
        },
    }


def headers(token: str, method: str = "tools/call", name: str = "health") -> dict[str, str]:
    return {
        "authorization": "Bearer " + token,
        "mcp-protocol-version": VERSION,
        "mcp-method": method,
        "mcp-name": name,
        "accept": "application/json, text/event-stream",
    }


@pytest.mark.asyncio
async def test_http_security_boundary(audit_db: Path) -> None:
    async with listener(audit_db) as (url, clients, settings):
        token, ref = clients.issue()
        good = headers(token.get_secret_value())
        async with httpx.AsyncClient(trust_env=False) as http:
            for changed, status in [
                ({"host": "evil.example"}, 421),
                ({"host": "127.0.0.1.evil.example"}, 421),
                ({"origin": "https://evil.example"}, 403),
                ({"origin": "null"}, 403),
                ({"authorization": ""}, 401),
                ({"authorization": "Bearer " + "x" * 43}, 401),
                ({"mcp-protocol-version": "2025-03-26"}, 400),
                ({"mcp-protocol-version": "2099-01-01"}, 400),
            ]:
                r = await http.post(url, headers={**good, **changed}, json=body())
                assert r.status_code == status
                assert token.get_secret_value() not in r.text
                print("HTTP boundary", list(changed)[0], status)
            for method in ["GET", "DELETE", "PUT", "OPTIONS"]:
                r = await http.request(method, url, headers=good)
                assert r.status_code == 405 and r.headers["allow"] == "POST"
            assert (await http.post(url + "/", headers=good, json=body())).status_code == 404
            for change in [{"mcp-method": "tools/list"}, {"mcp-name": "write_note"}]:
                r = await http.post(url, headers={**good, **change}, json=body())
                assert r.status_code == 400 and "error" in r.json()
                print("HTTP metadata mismatch", r.status_code, r.json()["error"]["code"])
            mismatch = body()
            mismatch["params"] = {
                "_meta": {PROTOCOL_VERSION_META_KEY: "2025-03-26", CLIENT_CAPABILITIES_META_KEY: {}}
            }
            r = await http.post(url, headers=good, json=mismatch)
            assert r.status_code == 400
            r = await http.post(url, headers=good, content="{", extensions={})
            assert r.status_code == 400
            # Explicit JSON content type for parser test.
            r = await http.post(
                url, headers={**good, "content-type": "application/json"}, content="{"
            )
            assert r.status_code == 400 and r.json()["error"]["code"] == -32700
            r = await http.post(url, headers=good, json=body("missing/method"))
            assert r.status_code == 400  # method header mismatch precedes unknown-method dispatch
            r = await http.post(
                url,
                headers=headers(token.get_secret_value(), "missing/method"),
                json=body("missing/method"),
            )
            assert r.status_code == 404
            r = await http.post(
                url,
                headers={**good, "content-type": "application/json"},
                content=b"x" * (settings.http.max_body_bytes + 1),
            )
            assert r.status_code == 413
            r = await http.post(
                url,
                headers={
                    **good,
                    "origin": url.removesuffix("/mcp"),
                    "x-forwarded-host": "evil.example",
                    "x-forwarded-for": "203.0.113.8",
                },
                json=body(),
            )
            assert r.status_code == 200 and "mcp-session-id" not in r.headers
            clients.revoke(ref.identifier)
            assert (await http.post(url, headers=good, json=body())).status_code == 401
            expired, expired_ref = clients.issue()
            clients.clock = lambda: expired_ref.expires
            expiry_response = await http.post(
                url, headers=headers(expired.get_secret_value()), json=body()
            )
            assert expiry_response.status_code == 401
        with AuditStore(audit_db).transaction() as db:
            assert db.execute("SELECT count(*) FROM audit_events").fetchone() == (2,)
        print("HTTP invalid transport requests created no audit/effect; safe call audited")


@pytest.mark.asyncio
async def test_http_rate_and_forged_context(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("mcp_agent_server.guardrails.rate_limiting._process", None)
    rate = {
        "connection_capacity": 1,
        "global_capacity": 2,
        "connection_refill": 0.001,
        "global_refill": 0.001,
    }
    async with listener(audit_db, rate=rate) as (url, clients, _):
        a, ar = clients.issue()
        b, _ = clients.issue()
        from mcp_agent_server.guardrails.approval import ApprovalGate
        from mcp_agent_server.guardrails.policy import load_policy
        from mcp_agent_server.tools.models import Message

        gate = ApprovalGate(AuditStore(audit_db), load_policy())
        msg = Message(recipient="ops-lab", subject="Limit", body="Synthetic")
        gate.issue(ar.authorization, "send_message", msg, issuer="test", ttl_seconds=60)
        async with httpx.AsyncClient(trust_env=False) as http:
            assert (
                await http.post(url, headers=headers(a.get_secret_value()), json=body())
            ).status_code == 200
            for name, args in [
                ("send_message", msg.model_dump()),
                ("write_note", {"title": "No", "body": "No"}),
            ]:
                data = body(name=name)
                data["params"] = {
                    "name": name,
                    "arguments": args,
                    "_meta": {
                        PROTOCOL_VERSION_META_KEY: VERSION,
                        CLIENT_CAPABILITIES_META_KEY: {},
                        "mcp-agent-server/idempotency-key": name,
                        "connection_id": "fresh",
                        "principal": "operator",
                        "session_id": "new",
                    },
                }
                r = await http.post(
                    url,
                    headers={
                        **headers(a.get_secret_value(), name=name),
                        "x-client-id": "new",
                        "x-role": "admin",
                    },
                    json=data,
                )
                assert r.json()["error"]["data"]["code"] == "rate_limit_exceeded"
            assert (
                "result"
                in (await http.post(url, headers=headers(b.get_secret_value()), json=body())).json()
            )
            # New capabilities/connections still share the global bucket.
            c, _ = clients.issue()
            results = await asyncio.gather(
                *(
                    http.post(url, headers=headers(c.get_secret_value()), json=body())
                    for _ in range(6)
                )
            )
            assert all(r.json()["error"]["data"]["code"] == "rate_limit_exceeded" for r in results)
        with gate.store.transaction() as db:
            assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (0,)
            assert db.execute("SELECT count(*) FROM notes").fetchone() == (0,)
            assert db.execute("SELECT count(*) FROM operations").fetchone() == (0,)
        print("HTTP rate: combined/global enforced; approval_consumed=0 notes=0 operations=0")
