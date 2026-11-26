import asyncio
import ssl
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from uuid import uuid4

import httpcore
import httpx
import pytest
from pydantic import BaseModel

from mcp_agent_server.adapters.http import MAX_BYTES, Fetcher, public_address
from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.config import Settings as ServerSettings
from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.guardrails.models import GuardrailExecution, GuardrailRequest
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.resilience.executor import ResilienceExecutor
from mcp_agent_server.resilience.models import Settings
from mcp_agent_server.tools.models import Fetch, Page

HOST = "docs.example.org"
IP = "93.184.216.34"
URL = "https://docs.example.org/guide"


@pytest.mark.parametrize(
    "value",
    [
        "http://docs.example.org",
        "file:///etc/passwd",
        "https://evil.example",
        "https://sub.docs.example.org",
        "https://docs.example.org.evil.org",
        "https://abc@docs.example.org",
        "https://docs.example.org:444",
        "https://%64ocs.example.org",
        "https://docs.example.org#token",
        "https://docs.example.org./",
        "https://docs.example.org\\@evil.org",
        "https://localhost",
        "https://host.internal",
        "https://bücher.org",
        "https://xn--bcher-kva.org",
        "https://2130706433",
        "https://0177.0.0.1",
        "https://0x7f000001",
        "https://[::ffff:127.0.0.1]",
        "https://[fd00::1]",
        "https://[::]",
        "https://127.0.0.1",
        "https://host.local",
        "https://docs.example.org\n/",
    ],
)
def test_invalid_destination(value: str) -> None:
    with pytest.raises(GuardrailError) as e:
        Fetcher((HOST,)).destination(value)
    assert e.value.public.code is ErrorCode.FETCH_DESTINATION_DENIED


@pytest.mark.parametrize(
    "ip",
    [
        "0.0.0.0",
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "169.254.169.254",
        "192.0.0.8",
        "192.88.99.1",
        "224.1.1.1",
        "255.255.255.255",
        "::1",
        "::",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "2002:7f00:1::",
        "64:ff9b::7f00:1",
        "2001:db8::1",
    ],
)
def test_prohibited_addresses(ip: str) -> None:
    with pytest.raises(GuardrailError) as e:
        public_address(ip)
    assert e.value.public.code is ErrorCode.FETCH_DNS_UNSAFE


def test_operator_allowlist() -> None:
    assert ServerSettings.from_env({}).fetch_hosts == ()
    with pytest.raises(GuardrailError):
        Fetcher(()).destination(URL)
    assert ServerSettings.from_env({"MCP_AGENT_FETCH_HOSTS": HOST.upper()}).fetch_hosts == (HOST,)
    for name in ["*." + HOST, "127.0.0.1", "foo.local", "localhost", "foo.xn--abc"]:
        with pytest.raises(ValueError):
            ServerSettings(fetch_hosts=(name,))


async def approved(host: str) -> Sequence[str]:
    assert host == HOST
    return [IP]


class Stream(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes):
        self.chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", ["mixed_dns", "redirect", "oversized", "binary", "encoding", "invalid_utf8", "nul"]
)
async def test_stream_restrictions(case: str) -> None:
    calls = 0

    async def dns(host: str) -> Sequence[str]:
        return [IP, "127.0.0.1"] if case == "mixed_dns" else [IP]

    def reply(req: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        headers = {"content-type": "image/png" if case == "binary" else "text/plain"}
        if case == "encoding":
            headers["content-encoding"] = "gzip"
        headers["location"] = "https://127.0.0.1/"
        chunks = {
            "oversized": (b"x" * MAX_BYTES, b"x"),
            "invalid_utf8": (b"\xff",),
            "nul": (b"a\0b",),
        }.get(case, (b"ok",))
        return httpx.Response(
            302 if case == "redirect" else 200, headers=headers, stream=Stream(*chunks)
        )

    f = Fetcher((HOST,), resolver=dns, transport=lambda: httpx.MockTransport(reply))
    with pytest.raises(GuardrailError) as e:
        await f._attempt(*f.destination(URL))
    assert calls == (0 if case == "mixed_dns" else 1)
    assert e.value.public.code == {
        "mixed_dns": ErrorCode.FETCH_DNS_UNSAFE,
        "oversized": ErrorCode.FETCH_RESPONSE_TOO_LARGE,
    }.get(case, ErrorCode.FETCH_RESPONSE_REJECTED)


@pytest.mark.asyncio
async def test_pinned_tcp_and_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Real HTTPX/httpcore and TLS parameters up to a synthetic socket. No Internet access."""
    from httpcore._backends.anyio import AnyIOBackend

    writes = []
    seen = []
    lookups = 0

    class Wire(httpcore.AsyncNetworkStream):
        async def start_tls(
            self,
            ssl_context: ssl.SSLContext,
            server_hostname: str | None = None,
            timeout: float | None = None,
        ) -> httpcore.AsyncNetworkStream:
            assert ssl_context.verify_mode == ssl.CERT_REQUIRED and ssl_context.check_hostname
            seen.append(server_hostname)
            return self

        async def write(self, buffer: bytes, timeout: float | None = None) -> None:
            writes.append(buffer)

        async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"

        async def aclose(self) -> None:
            pass

    async def tcp(self: AnyIOBackend, host: str, port: int, **kwargs: object) -> Wire:
        assert host == IP and port == 443
        seen.append(host)
        return Wire()

    async def rebinding(host: str) -> Sequence[str]:
        nonlocal lookups
        lookups += 1
        return [IP if lookups == 1 else "127.0.0.1"]

    monkeypatch.setattr(AnyIOBackend, "connect_tcp", tcp)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    f = Fetcher((HOST,), resolver=rebinding)
    page = await f._attempt(*f.destination(URL))
    assert page.text == "ok" and seen == [IP, HOST] and lookups == 1
    assert b"host: docs.example.org\r\n" in b"".join(writes).lower()
    print(f"TCP={IP}:443 SNI={HOST} certificate_check=required HTTP_Host={HOST} lookups={lookups}")


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["retry", "timeout", "breaker", "bulkhead"])
async def test_fetch_with_resilience(audit_db: Path, case: str) -> None:
    count = 0
    entered = asyncio.Event()
    release = asyncio.Event()

    async def reply(req: httpx.Request) -> httpx.Response:
        nonlocal count
        count += 1
        entered.set()
        if case == "timeout" or case == "bulkhead":
            await release.wait()
        if case == "breaker" or case == "retry" and count == 1:
            raise httpx.ConnectError("private diagnostic")
        return httpx.Response(200, headers={"content-type": "text/plain"}, stream=Stream(b"ok"))

    f = Fetcher((HOST,), resolver=approved, transport=lambda: httpx.MockTransport(reply))
    p = Pipeline(AuditStore(audit_db), {"fetch_url": Fetch}, 8192, 8)
    executor = ResilienceExecutor(
        p,
        {
            HOST: Settings(
                attempt_seconds=0.04 if case == "timeout" else 1.0,
                attempts=2,
                backoff_base=0,
                concurrency=1,
                queue_capacity=0,
                failure_threshold=1 if case == "breaker" else 3,
            )
        },
    )

    async def dispatch(args: BaseModel) -> Page:
        with p.handler("fetch_url"):
            return await f.fetch(URL, executor)

    async def call() -> tuple[GuardrailExecution, Page | None]:
        return await p.execute(
            GuardrailRequest(connection_id=uuid4(), tool_name="fetch_url", arguments={"url": URL}),
            dispatch,
        )

    if case == "bulkhead":
        owner = asyncio.create_task(call())
        async with asyncio.timeout(2):
            await entered.wait()
            outcome, _ = await call()
            assert outcome.error and outcome.error.code is ErrorCode.DEPENDENCY_UNAVAILABLE
            release.set()
            assert not (await owner)[0].error and count == 1
    else:
        outcome, page = await call()
        if case == "retry":
            assert page and page.text == "ok" and count == 2
        elif case == "timeout":
            assert outcome.error and outcome.error.code is ErrorCode.FETCH_TIMEOUT and count == 2
        else:
            again, _ = await call()
            assert again.error and outcome.error and count == 1
