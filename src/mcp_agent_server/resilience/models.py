from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

T = TypeVar("T")


class Settings(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", allow_inf_nan=False)
    total_seconds: float = Field(default=5.0, gt=0, le=300)
    attempt_seconds: float = Field(default=1.0, gt=0, le=300)
    attempts: int = Field(default=2, ge=1, le=16)
    backoff_base: float = Field(default=0.05, ge=0, le=60)
    backoff_cap: float = Field(default=1.0, ge=0, le=60)
    jitter: float = Field(default=0.0, ge=0, le=1)
    failure_threshold: int = Field(default=3, ge=1, le=1000)
    cooldown: float = Field(default=10.0, gt=0, le=3600)
    probes: int = Field(default=1, ge=1, le=32)
    concurrency: int = Field(default=4, ge=1, le=256)
    queue_capacity: int = Field(default=8, ge=0, le=1024)
    queue_seconds: float = Field(default=0.5, ge=0, le=300)

    @model_validator(mode="after")
    def valid_backoff(self) -> "Settings":
        if self.backoff_base > self.backoff_cap:
            raise ValueError("Backoff base exceeds cap")
        return self


class Safety(StrEnum):
    READ_ONLY = "read_only"
    UNSAFE_WRITE = "unsafe_write"


@dataclass(frozen=True)
class Operation(Generic[T]):
    dependency: str
    invoke: Callable[[], Awaitable[T]]
    safety: Safety = Safety.UNSAFE_WRITE


class ResilienceError(Exception):
    """Local operational failure. No dependency response body is included."""


class TransientFailure(ResilienceError):
    """Trusted adapter explicitly classifies a transient dependency failure."""


class AttemptTimeout(TransientFailure):
    pass


class DeadlineExceeded(ResilienceError):
    pass


class CircuitOpen(ResilienceError):
    pass


class BulkheadFull(ResilienceError):
    pass


class QueueTimeout(ResilienceError):
    pass
