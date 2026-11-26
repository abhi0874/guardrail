"""Actual pinned SDK serialization with fake HTTP; no real Gemini requests."""

import asyncio
import json
from typing import Any

import httpx2
import pytest
from pydantic import ValidationError

from mcp_agent_server.agent.gemini import BudgetTransport, Gemini, GeminiConfig, RequestBudget
from mcp_agent_server.agent.models import Definition, Message, ProviderError
from mcp_agent_server.tools.registry import SPECS

KEY = "synthetic_key_never_sent_to_a_public_service"
HISTORY = (
    Message(role="system", content="Use offered tools."),
    Message(role="user", content="Synthetic task."),
)
TOOLS = (
    Definition(
        name="write_note",
        description="A note.",
        parameters=SPECS["write_note"].arguments.model_json_schema(),
    ),
)


def envelope(parts: list[dict[str, Any]] | None = None, **changes: Any) -> dict[str, Any]:
    return {
        "candidates": [
            {
                "content": {"role": "model", "parts": parts or [{"text": "Done"}]},
                "finishReason": "STOP",
            }
        ],
        **changes,
    }


def provider(handler: Any, requests: int = 3) -> Gemini:
    return Gemini(
        GeminiConfig(model="gemini-synthetic", enabled=True, requests=requests),
        environment={"GEMINI_API_KEY": KEY},
        transport=httpx2.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_real_sdk_request_and_declared_tool_response() -> None:
    seen = []

    def handler(r: httpx2.Request) -> httpx2.Response:
        seen.append(r)
        assert r.url.host == "generativelanguage.googleapis.com" and r.url.path.endswith(
            "/gemini-synthetic:generateContent"
        )
        assert not r.url.query and r.headers["x-goog-api-key"] == KEY
        body = json.loads(r.content)
        assert body["systemInstruction"]["parts"][0]["text"] == "Use offered tools."
        assert body["tools"][0]["functionDeclarations"][0]["name"] == "write_note"
        assert not any(
            k in body["tools"][0] for k in ("googleSearch", "codeExecution", "urlContext")
        )
        return httpx2.Response(
            200,
            json=envelope(
                [
                    {
                        "functionCall": {
                            "name": "write_note",
                            "args": {"title": "Demo", "body": "Synthetic."},
                        }
                    }
                ]
            ),
        )

    p = provider(handler)
    reply = await p.respond(HISTORY, TOOLS)
    assert reply.calls[0].name == "write_note" and reply.calls[0].arguments["body"] == "Synthetic."
    assert len(seen) == p.counters.attempted == p.counters.successful == 1


@pytest.mark.asyncio
async def test_zero_offline_and_exhausted_budget() -> None:
    def forbidden(_: httpx2.Request) -> httpx2.Response:
        raise AssertionError("Network boundary reached")

    disabled = Gemini(
        GeminiConfig(model="gemini-synthetic"),
        environment={},
        transport=httpx2.MockTransport(forbidden),
    )
    with pytest.raises(ProviderError, match="remote_disabled"):
        await disabled.respond(HISTORY, TOOLS)
    zero = provider(forbidden, 0)
    with pytest.raises(ProviderError, match="budget_exhausted"):
        await zero.respond(HISTORY, TOOLS)
    assert zero.counters.attempted == 0 and zero.counters.denied == 1
    assert disabled.counters.attempted == 0


@pytest.mark.asyncio
async def test_concurrent_turns_share_hard_cap() -> None:
    seen = 0

    async def handler(_: httpx2.Request) -> httpx2.Response:
        nonlocal seen
        seen += 1
        await asyncio.sleep(0.001)
        return httpx2.Response(200, json=envelope())

    p = provider(handler)
    replies = await asyncio.gather(
        *(p.respond(HISTORY, ()) for _ in range(12)), return_exceptions=True
    )
    assert sum(isinstance(v, ProviderError) for v in replies) == 9
    assert seen == p.counters.attempted == p.counters.successful == 3
    assert p.counters.denied == 9
    with pytest.raises(ProviderError, match="budget_exhausted"):
        await p.respond(HISTORY, ())
    assert seen == 3


@pytest.mark.asyncio
async def test_retries_cannot_reset_boundary_budget() -> None:
    seen = 0

    def handler(_: httpx2.Request) -> httpx2.Response:
        nonlocal seen
        seen += 1
        return httpx2.Response(503, json={"error": {"message": KEY, "code": 503}})

    p = provider(handler)
    for _ in range(3):
        with pytest.raises(ProviderError, match="provider_unavailable"):
            await p.respond(HISTORY, ())
    with pytest.raises(ProviderError, match="budget_exhausted"):
        await p.respond(HISTORY, ())
    assert seen == p.counters.attempted == 3 and p.counters.successful == 0
    # Count any retry at the transport, even if a future SDK reintroduces automatic retries.
    budget = RequestBudget(1)
    boundary = BudgetTransport(httpx2.MockTransport(handler), budget, "gemini-synthetic")
    req = httpx2.Request(
        "POST",
        "https://generativelanguage.googleapis.com/v1/models/gemini-synthetic:generateContent",
    )
    with pytest.raises(ProviderError):
        await boundary.handle_async_request(req)
    with pytest.raises(ProviderError, match="budget_exhausted"):
        await boundary.handle_async_request(req)
    assert seen == 4 and budget.counters.attempted == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, "provider_auth"),
        (403, "provider_auth"),
        (429, "provider_quota"),
        (500, "provider_unavailable"),
        (302, "provider_unavailable"),
    ],
)
async def test_safe_failures(status: int, code: str) -> None:
    p = provider(lambda _: httpx2.Response(status, text=KEY))
    with pytest.raises(ProviderError) as caught:
        await p.respond(HISTORY, ())
    assert str(caught.value) == code and KEY not in repr(caught.value)
    assert p.counters.attempted == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b'{"candidates":NaN}',
        b'{"candidates":1e999}',
        json.dumps(envelope([{"functionCall": {"name": "issue_approval", "args": {}}}])).encode(),
        json.dumps(
            envelope(
                [
                    {
                        "functionCall": {
                            "name": "write_note",
                            "args": {"title": "x", "body": "x", "approval": True},
                        }
                    }
                ]
            )
        ).encode(),
        json.dumps(
            envelope(
                [
                    {
                        "functionCall": {
                            "name": "write_note",
                            "args": {"title": "x", "body": "x"},
                            "identity": "operator",
                        }
                    }
                ]
            )
        ).encode(),
        json.dumps(envelope([{"executableCode": {"code": "do evil"}}])).encode(),
        json.dumps(envelope([{"text": "Hello", "operatorApproved": True}])).encode(),
        json.dumps({"candidates": []}).encode(),
        b"x" * 65537,
    ],
)
async def test_reject_untrusted_response(raw: bytes) -> None:
    p = provider(lambda _: httpx2.Response(200, content=raw))
    with pytest.raises(ProviderError):
        await p.respond(HISTORY, TOOLS)
    assert p.counters.attempted == 1


@pytest.mark.asyncio
async def test_tool_role_and_opaque_signature_preserved_without_reasoning() -> None:
    n = 0

    def handler(r: httpx2.Request) -> httpx2.Response:
        nonlocal n
        n += 1
        if n == 1:
            return httpx2.Response(
                200,
                json=envelope(
                    [
                        {"thought": True, "text": "PRIVATE HIDDEN REASONING"},
                        {
                            "functionCall": {
                                "name": "write_note",
                                "id": "call-one",
                                "args": {"title": "x", "body": "y"},
                            },
                            "thoughtSignature": "c2lnbmF0dXJl",
                        },
                    ]
                ),
            )
        data = json.loads(r.content)
        text = json.dumps(data)
        assert "PRIVATE HIDDEN REASONING" not in text
        assert data["contents"][-1]["parts"][0]["functionResponse"]["name"] == "write_note"
        assert data["contents"][-1]["parts"][0]["functionResponse"]["id"] == "call-one"
        assert "thoughtSignature" in text
        return httpx2.Response(200, json=envelope())

    p = provider(handler)
    first = await p.respond(HISTORY, TOOLS)
    assert not first.content
    history = (
        *HISTORY,
        Message(role="assistant", content=first.content, calls=first.calls),
        Message(role="tool", tool_name="write_note", content='{"note_id":1,"persisted":true}'),
    )
    assert (await p.respond(history, TOOLS)).content == "Done"
    assert p.counters.attempted == 2


@pytest.mark.asyncio
async def test_cancellation_counts_attempt_without_retry() -> None:
    started = asyncio.Event()

    async def handler(_: httpx2.Request) -> httpx2.Response:
        started.set()
        await asyncio.Event().wait()
        raise AssertionError

    p = provider(handler)
    task = asyncio.create_task(p.respond(HISTORY, ()))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert p.counters.attempted == 1 and p.counters.successful == 0


@pytest.mark.parametrize(
    "change",
    [
        {"requests": 4},
        {"requests": True},
        {"seconds": float("nan")},
        {"model": "../other"},
        {"enabled": False, "requests": 1},
    ],
)
def test_config_rejects_unsafe_values(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        GeminiConfig.model_validate(
            {"model": "gemini-synthetic", "enabled": True, "requests": 3, **change}
        )


@pytest.mark.asyncio
async def test_deadline_stops_before_outbound_after_expensive_setup() -> None:
    def forbidden(_: httpx2.Request) -> httpx2.Response:
        raise AssertionError("Expired request reached transport")

    p = Gemini(
        GeminiConfig(model="gemini-synthetic", enabled=True, requests=3, seconds=0.000001),
        environment={"GEMINI_API_KEY": KEY},
        transport=httpx2.MockTransport(forbidden),
    )
    with pytest.raises(ProviderError, match="provider_timeout"):
        await p.respond(HISTORY, ())
    assert p.counters.attempted == 0


@pytest.mark.asyncio
async def test_ambient_provider_settings_cannot_change_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "https://untrusted.invalid")
    requests = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        assert request.url.host == "generativelanguage.googleapis.com"
        assert KEY.encode() not in request.content
        return httpx2.Response(200, json=envelope())

    p = provider(handler)
    await p.respond(HISTORY, ())
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_budget_endpoint_guard_and_transient_connection_errors() -> None:
    def handler(_: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError(KEY)

    budget = RequestBudget(3)
    boundary = BudgetTransport(httpx2.MockTransport(handler), budget, "gemini-synthetic")
    for url in (
        "http://generativelanguage.googleapis.com/v1/models/gemini-synthetic:generateContent",
        "https://untrusted.invalid/v1/models/gemini-synthetic:generateContent",
    ):
        with pytest.raises(ProviderError):
            await boundary.handle_async_request(httpx2.Request("POST", url))
    assert budget.counters.attempted == 0
    p = provider(handler)
    with pytest.raises(ProviderError, match="provider_unavailable"):
        await p.respond(HISTORY, ())
    assert p.counters.attempted == 1


@pytest.mark.asyncio
async def test_credential_echo_is_never_returned_or_dispatched() -> None:
    p = provider(lambda _: httpx2.Response(200, json=envelope([{"text": KEY}])))
    with pytest.raises(ProviderError, match="invalid_response") as caught:
        await p.respond(HISTORY, ())
    assert KEY not in str(caught.value)
    assert p.counters.attempted == 1


def test_cli_requires_explicit_gemini_opt_in(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    from mcp_agent_server.agent.__main__ import main

    monkeypatch.setattr("sys.argv", ["agent", "run", "--provider", "gemini"])
    assert main() == 2
    captured = capsys.readouterr()
    assert (
        not captured.out
        and captured.err == "Agent configuration, connection or recording failed.\n"
    )


@pytest.mark.asyncio
async def test_waiting_response_times_out_without_retry() -> None:
    async def handler(_: httpx2.Request) -> httpx2.Response:
        await asyncio.Event().wait()
        raise AssertionError

    p = Gemini(
        GeminiConfig(model="gemini-synthetic", enabled=True, requests=3, seconds=0.1),
        environment={"GEMINI_API_KEY": KEY},
        transport=httpx2.MockTransport(handler),
    )
    with pytest.raises(ProviderError, match="provider_timeout"):
        await p.respond(HISTORY, ())
    assert p.counters.attempted == 1 and p.counters.successful == 0
