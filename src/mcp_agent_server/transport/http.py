"""ASGI security boundary around the official SDK, with no custom JSON-RPC parser."""

import json
import logging
import os
import stat
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import uvicorn
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecurityMiddleware, TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from mcp_agent_server.config import PROJECT, Settings
from mcp_agent_server.guardrails.middleware import ToolMiddleware
from mcp_agent_server.logging import LOGGER

from .context import Clients
from .errors import safe_protocol_errors


class HTTPApplication:
    def __init__(
        self,
        server: MCPServer[None],
        settings: Settings,
        clients: Clients,
        cleanup: Callable[[], None] | None = None,
    ):
        guards = [m for m in server.middleware if isinstance(m, ToolMiddleware)]
        if len(guards) != 1 or guards[0].http_context != clients.resolve:
            raise ValueError("HTTP requires the matching trusted context resolver")
        if safe_protocol_errors not in server.middleware:
            server.middleware.insert(0, safe_protocol_errors)
        self.clients = clients
        self.cleanup = cleanup
        host = f"127.0.0.1:{settings.http.port}"
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[host],
            allowed_origins=[f"http://{host}"],
        )
        self.security = TransportSecurityMiddleware(security)
        self.app = server.streamable_http_app(
            host="127.0.0.1",
            stateless_http=True,
            json_response=False,
            transport_security=security,
            max_request_body_size=settings.http.max_body_bytes,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            try:
                await self.app(scope, receive, send)
            finally:
                if scope["type"] == "lifespan":
                    self.clients.clear()
                    if self.cleanup is not None:
                        self.cleanup()
            return
        request = Request(dict(scope), receive)
        response = await self.security.validate_request(request, is_post=request.method == "POST")
        sensitive = {b"host", b"origin", b"authorization", b"mcp-protocol-version"}
        names = [k for k, _ in scope["headers"] if k in sensitive]
        if len(names) != len(set(names)):
            response = Response("Duplicate security header", status_code=400)
        if response is None and request.url.path != "/mcp":
            response = Response(status_code=404)
        if response is None and request.method != "POST":
            response = Response(status_code=405, headers={"Allow": "POST"})
        if response is None and request.headers.get("mcp-protocol-version") != "2026-07-28":
            response = Response("Unsupported protocol version", status_code=400)
        if response is not None:
            await response(scope, receive, send)
            return
        reference = self.clients.authenticate(request.headers.get("authorization", ""))
        if reference is None:
            await Response("Local capability required", status_code=401)(scope, receive, send)
            return
        self.clients.bind(request, reference)
        await self.app(request.scope, receive, send)


def provision(clients: Clients) -> Path:
    """Write one local operator credential privately, never to a terminal or log."""
    directory = PROJECT / ".runtime/http"
    for parent in (directory, directory.parent, PROJECT):
        if parent.is_symlink():
            raise ValueError("Unsafe credential directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Credential directory must be private")
    token, reference = clients.issue()
    path = directory / f"client-{uuid4().hex}.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(
            {
                "token": token.get_secret_value(),
                "client_reference": str(reference.identifier),
                "ttl_seconds": clients.settings.ttl_seconds,
            },
            stream,
        )
    return path


def run_http(settings: Settings) -> None:
    from mcp_agent_server.server import create_server

    clients = Clients(settings.http)
    server = create_server(settings, http_context=clients.resolve)
    credential = provision(clients)
    app = HTTPApplication(server, settings, clients, lambda: credential.unlink(missing_ok=True))
    try:
        logging.getLogger(LOGGER).info("Local credential file: %s", credential.name)
        uvicorn.run(
            app,
            host=settings.http.host,
            port=settings.http.port,
            log_config=None,
            access_log=False,
            proxy_headers=False,
            server_header=False,
            limit_concurrency=128,
            timeout_keep_alive=5,
            timeout_graceful_shutdown=5,
        )
    finally:
        clients.clear()
        credential.unlink(missing_ok=True)
