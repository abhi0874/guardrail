"""Explicit Gemini opt-in; every HTTP attempt crosses one persistent run budget.

The SDK is imported lazily. No model/provider is required by server startup or replay.
Only primitive declarations are sent: SDK execution and continuation are disabled.
"""

import asyncio
import json
import os
from collections.abc import Mapping
from time import monotonic
from typing import Any, Literal

import httpx2
from pydantic import Field, JsonValue, SecretStr, ValidationError, model_validator

from ..tools.registry import SPECS
from .json_input import decode
from .models import Definition, Message, Provider, ProviderError, Reply, Strict, ToolCall

HOST = "generativelanguage.googleapis.com"
MAX_RESPONSE = 65536


class GeminiConfig(Strict):
    model: str = Field(pattern=r"^gemini-[a-z0-9][a-z0-9.-]{0,95}$")
    enabled: bool = False
    requests: int = Field(default=0, ge=0, le=3)
    seconds: float = Field(default=15, gt=0, le=30)
    key_variable: str = Field(default="GEMINI_API_KEY", pattern=r"^[A-Z][A-Z0-9_]{0,63}$")

    @model_validator(mode="after")
    def opt_in(self) -> "GeminiConfig":
        if not self.enabled and self.requests:
            raise ValueError("Offline mode requires zero requests")
        return self


class Counters(Strict):
    attempted: int
    successful: int
    denied: int


class RequestBudget:
    """No reset API. One instance is shared across all turns and concurrent sends."""

    def __init__(self, maximum: int = 0):
        if type(maximum) is not int or not 0 <= maximum <= 3:
            raise ValueError("Request budget must be an integer from zero through three")
        self._maximum = maximum
        self._attempted = self._successful = self._denied = 0
        self._lock = asyncio.Lock()

    @property
    def counters(self) -> Counters:
        return Counters(attempted=self._attempted, successful=self._successful, denied=self._denied)

    async def admit(self) -> None:
        async with self._lock:
            if self._attempted >= self._maximum:
                self._denied += 1
                raise ProviderError("budget_exhausted")
            # No refund for timeout/cancellation/connect error or a failed response.
            self._attempted += 1

    def success(self) -> None:
        self._successful += 1


class WireFunction(Strict):
    name: str = Field(max_length=64)
    args: dict[str, JsonValue] = Field(default_factory=dict, max_length=16)
    id: str | None = Field(default=None, max_length=128)


class WirePart(Strict):
    text: str | None = Field(default=None, max_length=8192)
    functionCall: WireFunction | None = None
    thought: bool = False
    thoughtSignature: str | None = Field(default=None, max_length=8192)

    @model_validator(mode="after")
    def shape(self) -> "WirePart":
        if (self.text is None) == (self.functionCall is None):
            raise ValueError("Exactly one supported part value is required")
        if self.thought and self.functionCall:
            raise ValueError("Thought parts cannot dispatch tools")
        return self


class WireContent(Strict):
    role: Literal["model"]
    parts: list[WirePart] = Field(min_length=1, max_length=16)


class WireCandidate(Strict):
    content: WireContent
    finishReason: Literal["STOP"]
    index: int = 0
    safetyRatings: list[dict[str, JsonValue]] | None = None
    citationMetadata: dict[str, JsonValue] | None = None
    avgLogprobs: float | None = None
    finishMessage: str | None = None
    tokenCount: int | None = None
    groundingMetadata: dict[str, JsonValue] | None = None
    logprobsResult: dict[str, JsonValue] | None = None


class WireResponse(Strict):
    candidates: list[WireCandidate] = Field(min_length=1, max_length=1)
    usageMetadata: dict[str, JsonValue] | None = None
    modelVersion: str | None = None
    responseId: str | None = None
    promptFeedback: dict[str, JsonValue] | None = None
    createTime: str | None = None
    modelStatus: dict[str, JsonValue] | None = None


class BudgetTransport(httpx2.AsyncBaseTransport):
    """The only underlying transport. Each delegate invocation is counted beforehand."""

    def __init__(
        self,
        inner: httpx2.AsyncBaseTransport,
        budget: RequestBudget,
        model: str,
        deadline: float | None = None,
    ):
        self._inner, self._budget = inner, budget
        self._deadline = deadline
        self._path = f"/v1/models/{model}:generateContent"

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        url = request.url
        if (
            request.method != "POST"
            or url.scheme != "https"
            or url.host != HOST
            or url.port not in (None, 443)
            or url.path != self._path
            or url.query
            or url.username
            or url.password
        ):
            raise ProviderError("provider_unavailable")
        if self._deadline is not None and monotonic() >= self._deadline:
            raise ProviderError("provider_timeout")
        await self._budget.admit()
        response = await self._inner.handle_async_request(request)
        try:
            if response.status_code in (401, 403):
                raise ProviderError("provider_auth")
            if response.status_code == 429:
                raise ProviderError("provider_quota")
            if not 200 <= response.status_code < 300:
                raise ProviderError("provider_unavailable")
            if response.headers.get("content-encoding", "identity") != "identity":
                raise ProviderError("invalid_response")
            data = bytearray()
            if response.is_stream_consumed:
                data.extend(response.content)
            else:
                async for chunk in response.aiter_raw(chunk_size=8192):
                    if len(data) + len(chunk) > MAX_RESPONSE:
                        raise ProviderError("response_limit")
                    data.extend(chunk)
            if len(data) > MAX_RESPONSE:
                raise ProviderError("response_limit")
            # Reject NaN, overflow, unsupported parts and privilege fields BEFORE SDK parsing.
            parsed = decode(data)
            WireResponse.model_validate(parsed)
            self._budget.success()
            return httpx2.Response(
                response.status_code,
                content=bytes(data),
                headers={"content-type": "application/json"},
                request=request,
            )
        except (ValueError, RecursionError, ValidationError):
            raise ProviderError("invalid_response") from None
        finally:
            await response.aclose()

    async def aclose(self) -> None:
        await self._inner.aclose()


class Gemini:
    provider: Provider = "gemini"

    def __init__(
        self,
        config: GeminiConfig,
        *,
        environment: Mapping[str, str] | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
    ):
        self.config = config
        self._budget = RequestBudget(config.requests)
        self._environment = environment
        self._transport = transport
        self._cache: dict[int, tuple[str, Any]] = {}

    @property
    def counters(self) -> Counters:
        return self._budget.counters

    async def respond(self, history: tuple[Message, ...], tools: tuple[Definition, ...]) -> Reply:
        if not self.config.enabled:
            raise ProviderError("remote_disabled")
        deadline = monotonic() + self.config.seconds
        env = os.environ if self._environment is None else self._environment
        key = env.get(self.config.key_variable, "")
        if not 16 <= len(key) <= 256 or not all(
            c.isascii() and (c.isalnum() or c in "_-") for c in key
        ):
            raise ProviderError("provider_auth")
        secret = SecretStr(key)
        if (
            not history
            or len(history) > 128
            or sum(len(m.model_dump_json()) for m in history) > 262144
        ):
            raise ProviderError("response_limit")
        if len(tools) > 6 or len({t.name for t in tools}) != len(tools):
            raise ProviderError("invalid_response")
        try:
            if len(json.dumps([t.model_dump() for t in tools], allow_nan=False)) > 65536:
                raise ProviderError("response_limit")
            # Only explicit provider selection reaches these optional imports.
            from google import genai
            from google.genai import types

            contents = []
            system = None
            pending: list[tuple[str, str | None]] = []
            for i, msg in enumerate(history):
                if msg.role == "system":
                    if i != 0:
                        raise ProviderError("invalid_response")
                    system = msg.content
                    continue
                fingerprint = msg.model_dump_json()
                cached = self._cache.get(i)
                if msg.role == "assistant":
                    if cached is not None:
                        if cached[0] != fingerprint:
                            raise ProviderError("invalid_response")
                        content = cached[1]
                    else:
                        parts = [types.Part(text=msg.content)] if msg.content else []
                        parts.extend(
                            types.Part(
                                function_call=types.FunctionCall(name=c.name, args=c.arguments)
                            )
                            for c in msg.calls
                        )
                        content = types.Content(role="model", parts=parts)
                    pending = [
                        (p.function_call.name, p.function_call.id)
                        for p in content.parts or []
                        if p.function_call
                    ]
                    contents.append(content)
                elif msg.role == "tool":
                    if not pending or pending[0][0] != msg.tool_name:
                        raise ProviderError("invalid_response")
                    name, callid = pending.pop(0)
                    contents.append(
                        types.Content(
                            role="user",
                            parts=[
                                types.Part(
                                    function_response=types.FunctionResponse(
                                        name=name,
                                        id=callid,
                                        response={"result": decode(msg.content)},
                                    )
                                )
                            ],
                        )
                    )
                else:
                    contents.append(
                        types.Content(role="user", parts=[types.Part(text=msg.content)])
                    )
            functions = [
                types.FunctionDeclaration(
                    name=t.name, description=t.description, parameters_json_schema=t.parameters
                )
                for t in tools
            ]
            cfg = types.GenerateContentConfig(
                system_instruction=system,
                tools=[types.Tool(function_declarations=functions)] if functions else None,
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                automatic_continuation=False,
                candidate_count=1,
                max_output_tokens=2048,
            )
            boundary = BudgetTransport(
                self._transport or httpx2.AsyncHTTPTransport(retries=0),
                self._budget,
                self.config.model,
                deadline,
            )
            async with (
                asyncio.timeout(max(0, deadline - monotonic())),
                httpx2.AsyncClient(
                    transport=boundary,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx2.Timeout(
                        self.config.seconds, connect=min(2, self.config.seconds)
                    ),
                    headers={"Accept-Encoding": "identity"},
                ) as http,
            ):
                with genai.Client(
                    api_key=secret.get_secret_value(),
                    vertexai=False,
                    enterprise=False,
                    http_options=types.HttpOptions(
                        base_url="https://" + HOST,
                        api_version="v1",
                        timeout=int(self.config.seconds * 1000),
                        httpx_async_client=http,
                        retry_options=types.HttpRetryOptions(attempts=1),
                    ),
                ) as client:
                    async with client.aio as api:
                        response = await api.models.generate_content(
                            model=self.config.model, contents=contents, config=cfg
                        )
            # A provider echo must never send the configured credential to a caller or MCP.
            if key in response.model_dump_json():
                raise ProviderError("invalid_response")
            # Only parts accepted by the strict transport schema can reach this point.
            candidate = (response.candidates or [])[0]
            content = candidate.content
            if content is None:
                raise ProviderError("invalid_response")
            text = []
            calls = []
            safe_parts = []
            allowed = {t.name for t in tools}
            for part in content.parts or []:
                if part.thought:
                    continue  # Never reveal or record hidden reasoning.
                if part.function_call:
                    call = part.function_call
                    if call.name not in allowed or call.name not in SPECS:
                        raise ProviderError("invalid_response")
                    args = call.args or {}
                    SPECS[call.name].arguments.model_validate(args)
                    calls.append(ToolCall(name=call.name, arguments=args))
                elif part.text is not None:
                    text.append(part.text)
                safe_parts.append(part)
            reply = Reply(content="".join(text), calls=tuple(calls))
            # Inspect the bounded final projection after all text parts are joined.
            # Reject the whole reply before cache, MCP dispatch or CLI output; masking
            # structured arguments could silently change an operation's meaning.
            if key in reply.content or key in reply.model_dump_json():
                raise ProviderError("invalid_response")
            message = Message(role="assistant", content=reply.content, calls=reply.calls)
            self._cache[len(history)] = (
                message.model_dump_json(),
                types.Content(role="model", parts=safe_parts),
            )
            if (
                len(self._cache) > 32
                or sum(len(v[0]) + len(v[1].model_dump_json()) for v in self._cache.values())
                > 262144
            ):
                raise ProviderError("response_limit")
            if monotonic() >= deadline:
                raise ProviderError("provider_timeout")
            return reply
        except ProviderError:
            raise
        except (TimeoutError, httpx2.TimeoutException):
            raise ProviderError("provider_timeout") from None
        except (ValueError, IndexError, KeyError, RecursionError, ValidationError):
            raise ProviderError("invalid_response") from None
        except Exception:
            # No SDK exception, credential, response body or prompt reaches logs/recordings.
            raise ProviderError("provider_unavailable") from None
