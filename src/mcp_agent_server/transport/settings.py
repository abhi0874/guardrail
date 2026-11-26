from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HTTPSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)
    enabled: bool = False
    host: Literal["127.0.0.1"] = "127.0.0.1"
    port: int = Field(default=8765, ge=1024, le=65535)
    max_clients: int = Field(default=128, ge=1, le=4096)
    ttl_seconds: float = Field(default=3600, ge=1, le=86400)
    max_body_bytes: int = Field(default=65536, ge=1024, le=1048576)
