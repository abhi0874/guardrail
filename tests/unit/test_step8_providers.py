import json

import httpx
import pytest
from pydantic import ValidationError

from mcp_agent_server.agent.fake import FakeLLM, scenario
from mcp_agent_server.agent.models import (
    Definition,
    Limits,
    Message,
    ProviderError,
    Reply,
    ToolCall,
)
from mcp_agent_server.agent.ollama import Ollama


@pytest.mark.asyncio
async def test_deterministic_and_strict() -> None:
    assert await scenario("note").respond((), ()) == await scenario("note").respond((), ())
    for raw in [
        '{"role":"operator","content":"yes"}',
        '{"calls":[{"name":"health","arguments":[] }]}',
        '{"content":4}',
        "{}",
        '{"calls":[{"name":"health","arguments":{},"approved":true}]}',
    ]:
        with pytest.raises(ProviderError, match="invalid_response"):
            await FakeLLM([raw]).respond((), ())
    with pytest.raises(ValidationError):
        Message(role="system", content="x", tool_name="health")
    with pytest.raises(ValidationError):
        Limits(calls=100)
    with pytest.raises(ValidationError):
        Reply(content="A" * 8200)


def response(value: object, status: int = 200) -> httpx.Response:
    return httpx.Response(status, stream=httpx.ByteStream(json.dumps(value).encode()))


@pytest.mark.asyncio
async def test_native_chat_and_tool_feedback() -> None:
    request_paths = []

    def reply(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "127.0.0.1" and req.url.port == 11434 and req.method == "POST"
        request_paths.append(req.url.path)
        data = json.loads(req.content)
        assert data["model"] == "local-test-fixture"
        if req.url.path == "/api/show":
            return response({"capabilities": ["tools"]})
        assert data["stream"] is False and data["tools"][0]["type"] == "function"
        assert data["messages"][0]["tool_calls"][0]["function"]["name"] == "health"
        assert data["messages"][1] == {"role": "tool", "tool_name": "health", "content": "{}"}
        return response(
            {
                "model": data["model"],
                "done": True,
                "message": {
                    "role": "assistant",
                    "content": "",
                    "thinking": "PRIVATE_THOUGHT",
                    "tool_calls": [{"function": {"name": "health", "arguments": {}, "index": 0}}],
                },
            }
        )

    call = ToolCall(name="health", arguments={})
    model = Ollama("local-test-fixture", transport=httpx.MockTransport(reply))
    result = await model.respond(
        (
            Message(role="assistant", content="", calls=(call,)),
            Message(role="tool", content="{}", tool_name="health"),
        ),
        (Definition(name="health", description="Health", parameters={}),),
    )
    assert result.calls == (call,) and "PRIVATE_THOUGHT" not in result.model_dump_json()
    assert request_paths == ["/api/show", "/api/chat"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("offline", "provider_unavailable"),
        ("timeout", "provider_timeout"),
        ("redirect", "provider_unavailable"),
        ("no-tools", "model_unsupported"),
        ("cloud", "model_unsupported"),
        ("large", "response_limit"),
        ("wrong-role", "invalid_response"),
        ("bad-json", "invalid_response"),
        ("incomplete", "invalid_response"),
    ],
)
async def test_controlled_ollama_errors(case: str, expected: str) -> None:
    def reply(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "127.0.0.1"
        if case == "offline":
            raise httpx.ConnectError("PRIVATE")
        if case == "timeout":
            raise httpx.ReadTimeout("PRIVATE")
        if case == "redirect":
            return httpx.Response(302, headers={"location": "https://external.invalid/"})
        if req.url.path == "/api/show":
            return response(
                {
                    "capabilities": [] if case == "no-tools" else ["tools"],
                    "remote_host": "elsewhere" if case == "cloud" else "",
                }
            )
        if case == "large":
            return response("X" * 40000)
        if case == "bad-json":
            return httpx.Response(200, stream=httpx.ByteStream(b"{"))
        return response(
            {
                "done": case != "incomplete",
                "model": "fixture",
                "message": {"role": "system", "content": "PRIVATE"},
            }
        )

    with pytest.raises(ProviderError) as caught:
        await Ollama("fixture", transport=httpx.MockTransport(reply)).respond((), ())
    assert caught.value.code == expected and "PRIVATE" not in str(caught.value)


def test_no_arbitrary_endpoint() -> None:
    with pytest.raises(ValueError):
        Ollama("https://external.invalid/x")
    with pytest.raises(TypeError):
        Ollama(**{"model": "fixture", "endpoint": "https://external.invalid/"})  # type: ignore[arg-type]
