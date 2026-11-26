"""A passive transcript with an allowlisted vocabulary and no executable payload."""

import fcntl
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, ValidationError, field_validator

from ..errors import ErrorCode
from .models import Failure, Provider, Strict, ToolName

Prompt = Literal["Run the synthetic demonstration.", "[withheld]"]
Answer = Literal["Synthetic demonstration complete.", "[withheld]"]
Reason = Literal[
    "complete",
    "turn_limit",
    "tool_limit",
    "history_limit",
    "deadline",
    "invalid_call",
    "tool_denied",
    "tool_error",
    "provider_error",
    "transport_error",
]


class Event(Strict):
    tool: ToolName | None
    # Position in the transcript identifies the intended operation within a run.
    outcome: Literal["ok", "denied", "error"]
    code: (
        ErrorCode
        | Literal[
            "unknown_tool", "invalid_arguments", "outside_scope", "tool_failure", "transport_error"
        ]
        | None
    ) = None
    request_id: UUID | None = None
    matches: int | None = Field(default=None, ge=0, le=5)
    persisted: bool | None = None
    replayed: bool | None = None
    disposition: Literal["allow", "warn"] | None = None
    simulated: bool | None = None
    elapsed_ms: int = Field(ge=0, le=120000)


class Recording(Strict):
    version: Literal[1]
    session: UUID
    provider: Provider
    prompt: Prompt
    tools: tuple[ToolName, ...] = Field(max_length=6)
    events: tuple[Event, ...] = Field(max_length=32)
    reason: Reason
    provider_error: Failure | None = None
    answer: Answer | None = None
    elapsed_ms: int = Field(ge=0, le=120000)

    @field_validator("version", mode="before")
    @classmethod
    def exact_version(cls, version: object) -> int:
        if type(version) is not int or version != 1:
            raise ValueError("Unsupported recording version")
        return version


MAX_BYTES = 32768


@contextmanager
def reserve(path: Path) -> Iterator[Callable[[Recording], None]]:
    """Pin every parent and the new inode. Never reopen, rename or unlink by pathname."""
    if not path.name or ".." in path.parts:
        raise ValueError("Unsafe recording path")
    absolute = path.absolute()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        parent = os.open(absolute.anchor, directory_flags)
        stack.callback(os.close, parent)
        for component in absolute.parts[1:-1]:
            parent = os.open(component, directory_flags, dir_fd=parent)
            stack.callback(os.close, parent)
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("Recording directory must be owner-controlled")
        fd = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        stream = stack.enter_context(os.fdopen(fd, "wb"))
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def check_owner() -> None:
            owned = os.fstat(fd)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if owned.st_nlink != 1 or not os.path.samestat(owned, named):
                raise ValueError("Recording destination changed")

        def finalize(recording: Recording) -> None:
            raw = recording.model_dump_json(indent=2).encode()
            if len(raw) > MAX_BYTES or stream.tell() != 0:
                raise ValueError("Invalid recording write")
            Recording.model_validate_json(raw)
            check_owner()
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
            check_owner()

        yield finalize


def save(path: Path, recording: Recording) -> None:
    with reserve(path) as finalize:
        finalize(recording)


def replay(path: Path) -> Recording:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Invalid recording file")
        fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Recording too large")
    try:
        return Recording.model_validate_json(raw)
    except ValidationError:
        raise ValueError("Invalid recording") from None
