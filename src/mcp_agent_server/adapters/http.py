"""Connect to a checked numeric address. The original name remains the TLS and HTTP authority."""

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Sequence
from urllib.parse import urlsplit

import httpx

from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.resilience.executor import ResilienceExecutor
from mcp_agent_server.resilience.models import (
    AttemptTimeout,
    DeadlineExceeded,
    Operation,
    ResilienceError,
    Safety,
    TransientFailure,
)
from mcp_agent_server.tools.models import Page

from .destinations import canonical_host

MAX_BYTES = 16_384
Resolver = Callable[[str], Awaitable[Sequence[str]]]


async def resolve(host: str) -> Sequence[str]:
    records = await asyncio.get_running_loop().getaddrinfo(host + ".", 443, type=socket.SOCK_STREAM)
    return [str(row[4][0]) for row in records]


def public_address(raw: str) -> str:
    try:
        ip = ipaddress.ip_address(raw)
        if (
            not ip.is_global
            or ip.is_multicast
            or ip.is_reserved
            or "%" in raw
            or isinstance(ip, ipaddress.IPv6Address)
            and (
                ip not in ipaddress.IPv6Network("2000::/3")
                or ip.sixtofour
                or ip.teredo
                or ip in ipaddress.IPv6Network("2001::/23")
                or ip in ipaddress.IPv6Network("3fff::/20")
            )
            or isinstance(ip, ipaddress.IPv4Address)
            and (
                ip in ipaddress.IPv4Network("192.0.0.0/24")
                or ip in ipaddress.IPv4Network("192.88.99.0/24")
            )
        ):
            raise ValueError
        return str(ip)
    except ValueError:
        raise GuardrailError(ErrorCode.FETCH_DNS_UNSAFE) from None


class Fetcher:
    def __init__(
        self,
        hosts: tuple[str, ...],
        *,
        resolver: Resolver = resolve,
        transport: Callable[[], httpx.AsyncBaseTransport] | None = None,
    ):
        self.hosts = frozenset(canonical_host(h) for h in hosts)
        self.resolver = resolver
        self.transport = transport or (
            lambda: httpx.AsyncHTTPTransport(verify=True, trust_env=False, retries=0)
        )

    def destination(self, url: str) -> tuple[str, httpx.URL]:
        try:
            if not url.isascii() or re.search(r"[\x00-\x20\x7f\\#]", url):
                raise ValueError
            parts = urlsplit(url)
            host = canonical_host(parts.hostname or "")
            if (
                parts.scheme != "https"
                or parts.netloc.lower() not in {host, host + ":443"}
                or host not in self.hosts
            ):
                raise ValueError
            parsed = httpx.URL(url)
            if parsed.host != host or parsed.scheme != "https":
                raise ValueError
            return host, parsed
        except (ValueError, httpx.InvalidURL):
            raise GuardrailError(ErrorCode.FETCH_DESTINATION_DENIED) from None

    async def fetch(self, url: str, executor: ResilienceExecutor) -> Page:
        host, target = self.destination(url)
        try:
            return await executor.run(
                Operation(host, lambda: self._attempt(host, target), Safety.READ_ONLY)
            )
        except (DeadlineExceeded, AttemptTimeout):
            raise GuardrailError(ErrorCode.FETCH_TIMEOUT) from None
        except ResilienceError:
            raise GuardrailError(ErrorCode.DEPENDENCY_UNAVAILABLE) from None

    async def _attempt(self, host: str, target: httpx.URL) -> Page:
        try:
            answers = await self.resolver(host)
            addresses = [public_address(ip) for ip in answers]
            if not addresses:
                raise GuardrailError(ErrorCode.FETCH_DNS_UNSAFE)
            # Fresh pool per attempt prevents reuse under another hostname at the same IP.
            pinned = target.copy_with(host=addresses[0])
            async with httpx.AsyncClient(
                transport=self.transport(), trust_env=False, follow_redirects=False, timeout=1
            ) as client:
                async with client.stream(
                    "GET",
                    pinned,
                    headers={"Host": host, "Accept-Encoding": "identity"},
                    extensions={"sni_hostname": host},
                ) as response:
                    if response.status_code in (502, 503, 504):
                        raise TransientFailure()
                    if (
                        response.status_code != 200
                        or response.headers.get("content-encoding", "identity").lower()
                        != "identity"
                    ):
                        raise GuardrailError(ErrorCode.FETCH_RESPONSE_REJECTED)
                    mime = response.headers.get("content-type", "").lower()
                    if not re.fullmatch(
                        r'text/(plain|markdown)(?:\s*;\s*charset=(?:utf-8|"utf-8"))?', mime
                    ):
                        raise GuardrailError(ErrorCode.FETCH_RESPONSE_REJECTED)
                    data = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(data) + len(chunk) > MAX_BYTES:
                            raise GuardrailError(ErrorCode.FETCH_RESPONSE_TOO_LARGE)
                        data.extend(chunk)
                    content = data.decode("utf-8")
                    if any(ord(c) < 32 and c not in "\r\n\t" or ord(c) == 127 for c in content):
                        raise GuardrailError(ErrorCode.FETCH_RESPONSE_REJECTED)
                    return Page(
                        host=host,
                        media_type="text/markdown"
                        if mime.startswith("text/markdown")
                        else "text/plain",
                        text=content,
                    )
        except UnicodeError:
            raise GuardrailError(ErrorCode.FETCH_RESPONSE_REJECTED) from None
        except httpx.TimeoutException:
            raise AttemptTimeout() from None
        except (socket.gaierror, httpx.NetworkError):
            raise TransientFailure() from None
        except httpx.HTTPError:
            raise GuardrailError(ErrorCode.DEPENDENCY_UNAVAILABLE) from None
