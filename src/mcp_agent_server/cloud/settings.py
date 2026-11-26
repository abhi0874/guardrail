import ipaddress
import json
import re
from collections.abc import Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class ClientGrant(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)
    identifier: UUID
    token: SecretStr = Field(repr=False, exclude=True)

    @model_validator(mode="after")
    def validate_token(self) -> "ClientGrant":
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", self.token.get_secret_value()):
            raise ValueError("High entropy operator credential required")
        return self


class CloudSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)
    port: int = Field(default=10000, ge=1024, le=65535)
    hosts: tuple[str, ...] = Field(min_length=1, max_length=8)
    origins: tuple[str, ...] = Field(min_length=1, max_length=8)
    trusted_proxies: tuple[str, ...] = Field(min_length=1, max_length=8)
    clients: tuple[ClientGrant, ...] = Field(min_length=1, max_length=16, repr=False, exclude=True)

    @model_validator(mode="after")
    def secure(self) -> "CloudSettings":
        for host in self.hosts:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host) or ".." in host:
                raise ValueError("Exact public host required")
        for origin in self.origins:
            if not origin.startswith("https://") or not re.fullmatch(r"[a-z0-9.-]+", origin[8:]):
                raise ValueError("Exact HTTPS origin required")
        for network in self.trusted_proxies:
            net = ipaddress.ip_network(network, strict=True)
            if net.prefixlen < (16 if net.version == 4 else 64):
                raise ValueError("Narrow verified proxy networks required")
        if len({c.identifier for c in self.clients}) != len(self.clients) or len(
            {c.token.get_secret_value() for c in self.clients}
        ) != len(self.clients):
            raise ValueError("Unique operator-provisioned client credentials required")
        return self

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "CloudSettings":
        return cls.model_validate(
            {
                "port": env.get("PORT", "10000"),
                "hosts": tuple(env.get("MCP_CLOUD_HOSTS", "").split(",")),
                "origins": tuple(env.get("MCP_CLOUD_ORIGINS", "").split(",")),
                "trusted_proxies": tuple(env.get("MCP_CLOUD_TRUSTED_PROXIES", "").split(",")),
                "clients": json.loads(env.get("MCP_CLOUD_CLIENTS", "[]")),
            }
        )
