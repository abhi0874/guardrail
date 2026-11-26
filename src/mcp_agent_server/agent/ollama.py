"""Native non-streaming Ollama adapter for an explicitly selected local model."""

import asyncio
import re
from typing import Any, Literal

import httpx
from pydantic import Field, ValidationError

from .json_input import decode
from .models import Definition, Message, Provider, ProviderError, Reply, Strict, ToolCall


class Function(ToolCall):
    index: int | None = Field(default=None, ge=0)


class WireCall(Strict):
    type: Literal["function"] = "function"
    function: Function


class WireMessage(Strict):
    role: Literal["assistant"]
    content: str
    thinking: str | None = None
    tool_calls: list[WireCall] = Field(default_factory=list, max_length=8)


class Ollama:
    provider: Provider = "ollama"

    def __init__(self, model: str, *, transport: httpx.AsyncBaseTransport | None = None):
        if (
            not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}", model)
            or "://" in model
            or model.lower().endswith(("cloud",))
        ):
            raise ValueError("Use an installed local model")
        self.model = model
        self._transport = transport

    async def _post(
        self, path: Literal["show", "chat"], payload: dict[str, Any], limit: int
    ) -> dict[str, Any]:
        try:
            async with (
                asyncio.timeout(20),
                httpx.AsyncClient(
                    trust_env=False,
                    follow_redirects=False,
                    transport=self._transport,
                    timeout=httpx.Timeout(15, connect=2),
                ) as client,
            ):
                async with client.stream(
                    "POST",
                    "http://127.0.0.1:11434/api/" + path,
                    json=payload,
                    headers={"Accept-Encoding": "identity"},
                ) as r:
                    if r.status_code != 200:
                        raise ProviderError("provider_unavailable")
                    if r.headers.get("content-encoding", "identity") != "identity":
                        raise ProviderError("invalid_response")
                    data = bytearray()
                    async for chunk in r.aiter_raw(chunk_size=8192):
                        if len(data) + len(chunk) > limit:
                            raise ProviderError("response_limit")
                        data.extend(chunk)
            parsed = decode(data)
            if not isinstance(parsed, dict):
                raise ProviderError("invalid_response")
            return parsed
        except (TimeoutError, httpx.TimeoutException):
            raise ProviderError("provider_timeout") from None
        except httpx.HTTPError:
            raise ProviderError("provider_unavailable") from None
        except (ValueError, RecursionError):
            raise ProviderError("invalid_response") from None

    async def respond(self, history: tuple[Message, ...], tools: tuple[Definition, ...]) -> Reply:
        info = await self._post("show", {"model": self.model}, 262144)
        caps = info.get("capabilities")
        if (
            not isinstance(caps, list)
            or "tools" not in caps
            or info.get("remote_model")
            or info.get("remote_host")
        ):
            raise ProviderError("model_unsupported")
        messages = []
        for msg in history:
            item: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.tool_name:
                item["tool_name"] = msg.tool_name
            if msg.calls:
                item["tool_calls"] = [{"function": c.model_dump()} for c in msg.calls]
            messages.append(item)
        data = await self._post(
            "chat",
            {
                "model": self.model,
                "stream": False,
                "messages": messages,
                "tools": [{"type": "function", "function": t.model_dump()} for t in tools],
            },
            32768,
        )
        if (
            data.get("done") is not True
            or data.get("done_reason", "stop") != "stop"
            or data.get("model") != self.model
        ):
            raise ProviderError("invalid_response")
        try:
            message = WireMessage.model_validate(data.get("message"))
            return Reply(
                content=message.content,
                calls=tuple(
                    ToolCall(name=c.function.name, arguments=c.function.arguments)
                    for c in message.tool_calls
                ),
            )
        except ValidationError:
            raise ProviderError("invalid_response") from None
