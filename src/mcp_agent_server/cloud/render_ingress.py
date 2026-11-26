"""Opt-in Render edge deployment; forwarding headers never establish authority."""

import json
from collections.abc import Mapping
from typing import Literal

from pydantic import Field
from starlette.requests import Request
from starlette.types import Receive, Scope, Send

from .app import CloudApplication
from .broker import Broker
from .settings import CloudSettings
from .storage import Sessions


class RenderSettings(CloudSettings):
    # This deployment has no proxy-address or client-IP trust model.
    trusted_proxies: tuple[str, ...] = Field(default=(), max_length=0)
    edge_https: Literal[True]

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "RenderSettings":
        if env.get("MCP_CLOUD_TRUSTED_PROXIES"):
            raise ValueError("Proxy trust is incompatible with Render edge ingress")
        return cls.model_validate(
            {
                "port": env.get("PORT", "10000"),
                "hosts": tuple(env.get("MCP_CLOUD_HOSTS", "").split(",")),
                "origins": tuple(env.get("MCP_CLOUD_ORIGINS", "").split(",")),
                "clients": json.loads(env.get("MCP_CLOUD_CLIENTS", "[]")),
                "edge_https": env.get("MCP_CLOUD_RENDER_EDGE_HTTPS") == "true",
            }
        )


class RenderIngress(CloudApplication):
    def __init__(self, config: RenderSettings, sessions: Sessions, broker: Broker):
        if not isinstance(config, RenderSettings) or config.edge_https is not True:
            raise ValueError("Explicit HTTPS-edge deployment acknowledgement required")
        super().__init__(config, sessions, broker)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Copy, never modify the upstream scope or synthesize a secure scheme/IP.
        # All authority comes from exact Host/Origin and configured Bearer grants.
        clean = dict(scope)
        clean["headers"] = [
            (name, value)
            for name, value in scope.get("headers", [])
            if name.lower() not in (b"forwarded", b"x-real-ip", b"cf-connecting-ip")
            and not name.lower().startswith(b"x-forwarded-")
        ]
        await super().__call__(clean, receive, send)

    def secure_transport(self, request: Request) -> bool:
        # Operator acknowledgement of documented edge TLS and origin isolation,
        # not a claim that this plaintext ASGI connection is cryptographically TLS.
        # This mode is unsuitable on a directly reachable/unprotected origin.
        return True
