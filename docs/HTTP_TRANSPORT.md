# Local Streamable HTTP (Step 7)

Stdio remains the default:
    uv run python -m mcp_agent_server

Opt in to HTTP:
    MCP_AGENT_HTTP_ENABLED=true uv run python -m mcp_agent_server

The endpoint is http://127.0.0.1:8765/mcp. Only 127.0.0.1 binding is accepted; nonprivileged
ports 1024–65535 can be selected with MCP_AGENT_HTTP_PORT. There are no admin, approval,
database or unrelated REST routes. The exact /mcp path is required, with no redirect.
The original MCP_AGENT_TRANSPORT setting remains stdio-only; HTTP uses its explicit
enabled flag so existing stdio configuration validation stays intact.

## Verified SDK contract

The locked MCP SDK is 2.3.0, protocol 2026-07-28. Its public
MCPServer.streamable_http_app builds the ASGI application. Uvicorn 0.54.0 runs it; Starlette
1.10.0 supplies request/response types. No FastAPI or custom JSON-RPC parser is used.
The SDK runner supplies the actual Starlette request through ServerRequestContext.request.
The HTTP wrapper adds a server-owned reference to its per-request scope; ToolMiddleware
resolves it through the matching capability registry. No shared identity ContextVar exists.

MCP 2026-07-28 has no protocol-level sessions. Each POST carries its version, client
capabilities and routing information. The SDK validates Mcp-Method, Mcp-Name and body
metadata agreement. It handles malformed JSON, unknown methods, result envelopes and
HTTP status mapping. No initialize handshake, mandatory Mcp-Session-Id, legacy GET/SSE
stream or DELETE session endpoint is added. The local wrapper accepts only version
2026-07-28, even though the SDK itself supports older revisions.

POST supports the SDK's JSON or request-scoped SSE response path. Clients advertise
application/json and text/event-stream. Fast calls resolve as JSON. SSE mode retains
the SDK's disconnect cancellation watcher; it is not a legacy standalone GET stream.
Request bodies are bounded by the SDK before parsing, including streamed bodies.

Version-matched references:
- https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/docs/run/deploy.md
- https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/docs/migration.md

## Transport and authentication order

The SDK transport-security validator checks exact Host 127.0.0.1:configured-port and
Origin http://127.0.0.1:configured-port. Other origins (including null) are refused.
Missing Origin is permitted for non-browser local clients, but never bypasses capability
authentication. DNS rebinding protection stays enabled. No CORS middleware or wildcard
is configured. Forwarded headers are ignored by the ASGI runner; they cannot supply identity,
Host authority or a rate bucket. Duplicate security headers are refused.

After Host/Origin, the wrapper checks route/method/version and local Bearer capability,
then delegates parsing and protocol validation to the SDK. Registered tools use current
policy, client/global rate admission, approval and idempotency, durable pre-audit, execution,
output guards and durable post-audit. Errors rejected before tool middleware have no
fabricated SQLite event. Tool requests retain fresh request IDs and trusted client UUIDs.

Observed status contracts:
- 421 invalid Host; 403 invalid Origin; 401 missing/expired/revoked capability.
- 405 unsupported HTTP method; 404 unknown route; 400 unsupported transport version.
- SDK 400 for header/body mismatch (code -32020) or invalid JSON (-32700).
- SDK 404 for unknown MCP method; 413 oversized body.
- Application errors carry existing safe codes in JSON-RPC error data, often with HTTP 200.

## Settings

All settings use the MCP_AGENT_HTTP_ prefix:
| Suffix | Default | Bounds |
| --- | --- | --- |
| ENABLED | false | explicit true/false |
| HOST | 127.0.0.1 | only this IPv4 loopback address |
| PORT | 8765 | 1024–65535 |
| MAX_CLIENTS | 128 | 1–4096 |
| TTL_SECONDS | 3600 | 1–86400, finite |
| MAX_BODY_BYTES | 65536 | 1024–1048576 |

The CLI permits at most 128 concurrent connections/tasks through Uvicorn, uses five-second
keepalive and graceful-shutdown limits, disables proxy-header trust and access logs, and
uses the existing JSON logging configuration. Third-party exception details are excluded
from diagnostics. There are no background credential reaper tasks.

## Client example

The CLI creates one owner-only capability file; see SESSION_SECURITY.md. Supply its token
as a Bearer header to the official client without printing it:

    import json
    from pathlib import Path
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    async def probe(credential_path: Path):
        value = json.loads(credential_path.read_text())
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + value["token"]}, trust_env=False
        ) as http:
            async with Client(streamable_http_client(
                "http://127.0.0.1:8765/mcp", http_client=http
            )) as client:
                return await client.call_tool("health")

The locked SDK uses httpx2 for its client transport. The server's existing fetch adapter
continues using its locked HTTPX 0.28.1. No external endpoint is required.

## Lifecycle and verification

A normal SIGTERM drains/cancels work, closes the SDK lifespan, clears capabilities and removes
the CLI credential file. Uvicorn re-raises SIGTERM after graceful cleanup: a subprocess may
report -15, not zero. An occupied port exits 3; invalid application configuration exits 2.
Abrupt SIGKILL cannot run cleanup, but credentials from that process are invalid after restart.

Cancellation never reissues a mutation grant. A committed note can survive a lost response
or failed post-audit; its duplicate must use the same key and capability. Uncertainty remains
explicit. A newly issued capability cannot replay an earlier client's result.

Run:
    uv run pytest -qs --no-cov tests/integration/test_http_*.py tests/security/test_http_security.py
    uv run pytest -qs --no-cov tests/integration/test_mcp_stdio.py
    uv run pytest -q

Listener tests bind actual 127.0.0.1 sockets and use the official client. Allowed fetch
responses are controlled fixtures. Offline acceptance separately proves external IP denial
and uses a loopback-only policy for HTTP. Do not claim a real listener works under a policy
that denies all loopback connections.

This is local single-worker capability authentication, not OAuth, remote-user authentication,
TLS termination or an Internet-safe deployment. Step 8 and Step 11 remain unimplemented.

## Step 7 protocol-error correction

The HTTP application installs `safe_protocol_errors` through the SDK's public middleware
list. SDK method-not-found errors outside tools/call are replaced with a fresh MCPError
carrying code -32601 and fixed message `Method not found`, with no data. This removes the
SDK's reflected method string, including nested data if supplied by an SDK middleware.
The SDK still owns request validation, correlation IDs, HTTP status 404, JSON-RPC envelopes
and streaming. Other error codes and ordinary tool errors remain unchanged. No SDK globals
or wire parsers are patched. The customization uses the pinned SDK's provisional public
middleware API and must be reverified on SDK upgrades.

Real-listener regression tests exercise configured canaries, long names, Unicode header
mismatch rejection, adjacent protocol/security errors, official-client parsing, and zero
business/audit effects for unknown methods. JSON-RPC correlation IDs are preserved; clients
must not use secret material as IDs. See tests/security/test_http_protocol_errors.py.
