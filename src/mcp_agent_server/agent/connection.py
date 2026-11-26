"""Operator-selected official client transports."""

import json
import os
import re
import stat
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TextIO

import httpx2
from mcp import Client, StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client


def read_token(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if (
            not stat.S_ISREG(st.st_mode)
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_uid != os.getuid()
        ):
            raise ValueError("Private capability file required")
        raw = f.read(4097)
    if len(raw) > 4096:
        raise ValueError("Invalid capability file")
    try:
        token = json.loads(raw)["token"]
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise ValueError("Invalid capability file") from None
    return token


@asynccontextmanager
async def connect(
    *,
    credential: Path | None = None,
    port: int = 8765,
    audit_db: Path | None = None,
    isolated: bool = False,
    errlog: TextIO | None = None,
) -> AsyncIterator[Client]:
    if credential is not None:
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("Invalid port")
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + read_token(credential)},
            trust_env=False,
            follow_redirects=False,
        ) as http:
            async with Client(
                streamable_http_client(f"http://127.0.0.1:{port}/mcp", http_client=http),
                read_timeout_seconds=15,
            ) as client:
                yield client
    else:
        env = {
            k: v
            for k, v in os.environ.items()
            if k.startswith("MCP_AGENT_") and not k.startswith("MCP_AGENT_HTTP_")
        }
        if isolated:
            env = {}
        if audit_db is not None:
            env["MCP_AGENT_AUDIT_DB"] = str(audit_db)
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "mcp_agent_server"], env=env
        )
        async with Client(
            stdio_client(params, errlog=errlog or sys.stderr), read_timeout_seconds=15
        ) as client:
            yield client
