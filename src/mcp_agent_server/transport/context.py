"""Operator-only capability registry. Credentials are never MCP session identifiers."""

import hashlib
import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID, uuid4

from pydantic import SecretStr
from starlette.requests import Request

from mcp_agent_server.guardrails.authorization import AuthorizationContext, Identity

from .settings import HTTPSettings

HTTP_IDENTITY = Identity(principal="local-capability")


@dataclass(frozen=True)
class ClientReference:
    identifier: UUID
    expires: float

    @property
    def authorization(self) -> AuthorizationContext:
        return AuthorizationContext(identity=HTTP_IDENTITY, connection_id=self.identifier)


class Clients:
    def __init__(self, settings: HTTPSettings, clock: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, ClientReference] = {}
        self._scope_key = "mcp-agent-server/trusted-client"

    def _now(self) -> float:
        now = self.clock()
        if not math.isfinite(now):
            raise ValueError("Invalid capability clock")
        return now

    def issue(self, *, identifier: UUID | None = None) -> tuple[SecretStr, ClientReference]:
        with self._lock:
            now = self._now()
            self._entries = {k: v for k, v in self._entries.items() if v.expires > now}
            if len(self._entries) >= self.settings.max_clients:
                raise ValueError("Client capacity reached")
            token = secrets.token_urlsafe(32)
            ref = ClientReference(identifier or uuid4(), now + self.settings.ttl_seconds)
            self._entries[hashlib.sha256(token.encode()).hexdigest()] = ref
            return SecretStr(token), ref

    def authenticate(self, header: str) -> ClientReference | None:
        if not header.startswith("Bearer ") or len(header) != 50:
            return None
        digest = hashlib.sha256(header[7:].encode()).hexdigest()
        with self._lock:
            ref = self._entries.get(digest)
            if ref is not None and ref.expires <= self._now():
                del self._entries[digest]
                return None
            return ref

    def revoke_token(self, token: SecretStr) -> None:
        """Operator-owned per-call capability cleanup without revoking concurrent calls."""
        digest = hashlib.sha256(token.get_secret_value().encode()).hexdigest()
        with self._lock:
            self._entries.pop(digest, None)

    def revoke(self, reference: UUID) -> None:
        with self._lock:
            self._entries = {k: v for k, v in self._entries.items() if v.identifier != reference}

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def bind(self, request: Request, reference: ClientReference) -> None:
        request.scope[self._scope_key] = reference

    def resolve(self, request: object) -> AuthorizationContext:
        if not isinstance(request, Request):
            raise ValueError("HTTP context required")
        ref = request.scope.get(self._scope_key)
        with self._lock:
            if (
                not isinstance(ref, ClientReference)
                or ref.expires <= self._now()
                or not any(value is ref for value in self._entries.values())
            ):
                raise ValueError("HTTP context unavailable")
        return ref.authorization
