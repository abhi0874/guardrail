"""Assembled Gemini output is inspected before it can reach any consumer."""

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import pytest

from mcp_agent_server.agent.gemini import Gemini, GeminiConfig
from mcp_agent_server.agent.models import Definition, Message, ProviderError
from mcp_agent_server.tools.registry import SPECS

KEY = "synthetic_configured_credential_for_output_tests"
HISTORY = (Message(role="user", content="Synthetic validation."),)
TOOLS = tuple(
    Definition(
        name=name,
        description="Synthetic tool.",
        parameters=SPECS[name].arguments.model_json_schema(),
    )
    for name in ("health", "write_note")
)


def wire(parts: list[dict[str, Any]]) -> dict[str, Any]:
    return {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP"}]}


def parts(count: int) -> list[dict[str, Any]]:
    return [
        {"text": KEY[i * len(KEY) // count : (i + 1) * len(KEY) // count]} for i in range(count)
    ]


def provider(raw: bytes) -> Gemini:
    return Gemini(
        GeminiConfig(model="gemini-synthetic", enabled=True, requests=3),
        environment={"GEMINI_API_KEY": KEY},
        transport=httpx2.MockTransport(lambda _: httpx2.Response(200, content=raw)),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 2, 3, 7])
@pytest.mark.parametrize("mixed", [False, True])
async def test_configured_key_rejected_after_complete_assembly(
    count: int,
    mixed: bool,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = parts(count)
    if mixed:
        payload.insert(1, {"functionCall": {"name": "health", "args": {}}})
    p = provider(json.dumps(wire(payload)).encode())
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ProviderError, match="invalid_response") as caught:
        await p.respond(HISTORY, TOOLS)
    out = capsys.readouterr()
    assert KEY not in out.out + out.err + caplog.text + repr(caught.value)
    assert p.counters.attempted == 1 and p.counters.successful == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["title", "body", "id"])
async def test_structured_output_uses_same_credential_rejection(field: str) -> None:
    call: dict[str, Any] = {
        "name": "write_note",
        "args": {"title": "Synthetic", "body": "Synthetic"},
    }
    if field == "id":
        call["id"] = KEY
    else:
        call["args"][field] = KEY
    p = provider(json.dumps(wire([{"functionCall": call}])).encode())
    with pytest.raises(ProviderError, match="invalid_response") as caught:
        await p.respond(HISTORY, TOOLS)
    assert KEY not in str(caught.value)
    assert p.counters.attempted == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mixed", [False, True])
async def test_legitimate_multipart_output_remains_functional(mixed: bool) -> None:
    payload: list[dict[str, Any]] = [{"text": "A valid "}, {"text": "multi-part answer."}]
    if mixed:
        payload.insert(1, {"functionCall": {"name": "health", "args": {}}})
    p = provider(json.dumps(wire(payload)).encode())
    result = await p.respond(HISTORY, TOOLS)
    assert result.content == "A valid multi-part answer."
    assert [c.name for c in result.calls] == (["health"] if mixed else [])
    assert not result.calls or result.calls[0].arguments == {}
    assert p.counters.attempted == p.counters.successful == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b'{"candidates":', "invalid_response"),
        (
            json.dumps(wire([{"text": "x" * 8192}, {"text": "y" * 8192}])).encode(),
            "invalid_response",
        ),
        (b"x" * 65537, "response_limit"),
    ],
)
async def test_uninspectable_output_fails_closed(
    raw: bytes, code: str, capsys: pytest.CaptureFixture[str]
) -> None:
    p = provider(raw)
    with pytest.raises(ProviderError) as caught:
        await p.respond(HISTORY, TOOLS)
    assert str(caught.value) == code
    out = capsys.readouterr()
    assert not out.out and KEY not in out.err
    assert p.counters.attempted == 1


@pytest.mark.asyncio
async def test_transport_chunks_never_emit_intermediate_fragments(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    started, release = asyncio.Event(), asyncio.Event()
    payload = json.dumps(wire(parts(2))).encode()
    cut = payload.index(KEY[: len(KEY) // 2].encode()) + len(KEY) // 2

    class Chunked(httpx2.AsyncByteStream):
        closed = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield payload[:cut]
            started.set()
            await release.wait()
            yield payload[cut:]

        async def aclose(self) -> None:
            self.closed = True

    stream = Chunked()
    p = Gemini(
        GeminiConfig(model="gemini-synthetic", enabled=True, requests=3),
        environment={"GEMINI_API_KEY": KEY},
        transport=httpx2.MockTransport(lambda _: httpx2.Response(200, stream=stream)),
    )
    caplog.set_level(logging.DEBUG)
    task = asyncio.create_task(p.respond(HISTORY, TOOLS))
    try:
        await asyncio.wait_for(started.wait(), 2)
        assert not task.done()
        out = capsys.readouterr()
        assert not out.out and KEY[: len(KEY) // 2] not in out.err + caplog.text
    finally:
        release.set()
    with pytest.raises(ProviderError, match="invalid_response"):
        await task
    out = capsys.readouterr()
    for fragment in (KEY[: len(KEY) // 2], KEY[len(KEY) // 2 :]):
        assert fragment not in out.out + out.err + caplog.text
    assert stream.closed and p.counters.attempted == 1
