from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from integration.http_support import client, listener
from mcp import MCPError
from mcp.shared.inbound import encode_header_value
from mcp_types import EmptyResult, JSONRPCError, Request, RequestParams

from mcp_agent_server.adapters.outbox import Outbox
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.policy import load_policy
from mcp_agent_server.tools.models import Message

from .test_http_security import body, headers

CANARY = "SYNTHETIC_PROTOCOL_CANARY"


@pytest.mark.asyncio
@pytest.mark.parametrize("method", [CANARY, CANARY + "雪\u202e", CANARY + "x" * 4096])
async def test_unknown_method_safe_on_real_wire(
    audit_db: Path, caplog: pytest.LogCaptureFixture, method: str
) -> None:
    outbox = Outbox()
    async with listener(audit_db, outbox=outbox, output={"literals": [CANARY]}) as (
        url,
        clients,
        _,
    ):
        token, ref = clients.issue()
        gate = ApprovalGate(AuditStore(audit_db), load_policy())
        gate.issue(
            ref.authorization,
            "send_message",
            Message(recipient="ops-lab", subject="Safe", body="Synthetic"),
            issuer="test",
            ttl_seconds=60,
        )
        packet = cast(dict[str, Any], body(method))
        packet["id"] = "correlation-17"
        packet["params"]["_meta"]["nested"] = {"data": [CANARY]}
        async with httpx.AsyncClient(trust_env=False) as raw:
            response = await raw.post(
                url,
                headers=headers(token.get_secret_value(), encode_header_value(method)),
                json=packet,
            )
        assert response.status_code == (400 if "雪" in method else 404)
        envelope = JSONRPCError.model_validate_json(response.text)
        assert envelope.id == "correlation-17" and envelope.jsonrpc == "2.0"
        assert envelope.error.code == (-32020 if "雪" in method else -32601)
        if "雪" not in method:
            assert envelope.error.message == "Method not found"
        assert "data" not in response.json()["error"]
        assert CANARY not in response.text and CANARY not in caplog.text
        with gate.store.transaction() as db:
            for table in ["audit_events", "operations", "notes"]:
                assert db.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)
            assert db.execute("SELECT count(consumed_event) FROM approvals").fetchone() == (0,)
        assert not outbox.entries
        assert CANARY.encode() not in audit_db.read_bytes()
        async with client(url, token) as official:
            with pytest.raises(MCPError) as error:
                await official.session.send_request(
                    Request[RequestParams, str](method="missing/method", params=RequestParams()),
                    EmptyResult,
                )
            assert error.value.code == -32601 and error.value.data is None
            assert error.value.message == "Method not found"
            assert (await official.call_tool("health")).structured_content
        print("safe_unknown_method", response.status_code, response.text)


@pytest.mark.asyncio
async def test_adjacent_protocol_errors(audit_db: Path) -> None:
    async with listener(audit_db, output={"literals": [CANARY]}) as (url, clients, _):
        token, _ = clients.issue()
        good = headers(token.get_secret_value())
        cases: list[tuple[object, dict[str, str], int]] = []
        invalid = cast(dict[str, Any], body())
        invalid["method"] = {"nested": [CANARY]}
        cases.append((invalid, {}, 400))
        cases.append((body(), {"mcp-protocol-version": CANARY}, 400))
        cases.append((body(), {"mcp-method": CANARY}, 400))
        args = cast(dict[str, Any], body())
        args["params"]["arguments"] = {"nested": [CANARY]}
        cases.append((args, {}, 400))
        cases.append(([CANARY], {}, 400))
        cases.append((body(), {"content-type": "text/" + CANARY}, 400))
        cases.append((body(), {"authorization": "Bearer " + CANARY}, 401))
        cases.append((body(), {"host": CANARY}, 421))
        cases.append((body(), {"origin": "https://" + CANARY}, 403))
        denial = cast(dict[str, Any], body(name="read_document"))
        denial["params"]["arguments"] = {"document_id": "unapproved"}
        cases.append((denial, {"mcp-name": "read_document"}, 200))
        async with httpx.AsyncClient(trust_env=False) as raw:
            for payload, changes, expected in cases:
                r = await raw.post(url, headers={**good, **changes}, json=payload)
                assert r.status_code == expected
                assert CANARY not in r.text
                print("adjacent_error", expected, r.text)
            r = await raw.post(
                url, headers={**good, "content-type": "application/json"}, content='{"' + CANARY
            )
            assert r.status_code == 400 and CANARY not in r.text
        assert CANARY.encode() not in audit_db.read_bytes()


@pytest.mark.asyncio
async def test_nested_sdk_error_data_is_dropped(
    audit_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp.server.context import CallNext, HandlerResult, ServerRequestContext

    from mcp_agent_server.server import create_server

    original = create_server

    async def injected(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        if ctx.method == "synthetic/error":
            raise MCPError(-32601, CANARY, {"nested": [{"value": CANARY}]})
        return await call_next(ctx)

    def factory(*args: Any, **kwargs: Any) -> Any:
        server = original(*args, **kwargs)
        server.middleware.append(injected)
        return server

    monkeypatch.setattr("integration.http_support.create_server", factory)
    async with listener(audit_db) as (url, clients, _):
        token, _ = clients.issue()
        async with httpx.AsyncClient(trust_env=False) as raw:
            r = await raw.post(
                url,
                headers=headers(token.get_secret_value(), "synthetic/error"),
                json=body("synthetic/error"),
            )
        assert r.status_code == 404
        assert r.json() == {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "Method not found"},
        }
        assert CANARY not in r.text
