"""Only server-owned credentials reach the official loopback MCP client."""

import json
import logging
from uuid import UUID

import httpx2
from mcp import Client, MCPError, types
from mcp.client.streamable_http import streamable_http_client
from pydantic import TypeAdapter

from mcp_agent_server.errors import ErrorCode
from mcp_agent_server.logging import LOGGER
from mcp_agent_server.tools.registry import SPECS
from mcp_agent_server.transport.context import Clients


class DeniedKeyConflict(Exception):
    """Binding conflict returned by the guarded call before dispatch."""


def _binding_conflict(error: MCPError) -> bool:
    data = error.data
    if error.code != -32000 or not isinstance(data, dict):
        return False
    if data.get("code") != ErrorCode.IDEMPOTENCY_KEY_CONFLICT or data.get("retryable") is not False:
        return False
    request_id = data.get("request_id")
    if not isinstance(request_id, str):
        return False
    try:
        return str(UUID(request_id)) == request_id
    except ValueError:
        return False


def validate_listing(listing: types.ListToolsResult) -> None:
    """Pin both schemas before dispatch, including the SDK's output validator."""
    if listing.next_cursor or sorted(t.name for t in listing.tools) != sorted(SPECS):
        raise ValueError("Unexpected internal tool contracts")
    for tool in listing.tools:
        spec = SPECS[tool.name]
        arguments = spec.arguments.model_json_schema()
        arguments["title"] = f"{tool.name}Arguments"
        arguments.pop("additionalProperties")
        expected = (arguments, spec.result.model_json_schema())
        actual = (tool.input_schema, tool.output_schema)
        if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError("Unexpected internal tool contracts")


class Broker:
    def __init__(self, url: str, clients: Clients):
        self.url, self.clients = url, clients

    async def call(
        self, identifier: UUID, tool: str, arguments: dict[str, object], key: str | None
    ) -> dict[str, object]:
        token, reference = self.clients.issue(identifier=identifier)
        confirmed: dict[str, object] | None = None
        try:
            async with httpx2.AsyncClient(
                headers={"Authorization": "Bearer " + token.get_secret_value()},
                trust_env=False,
                timeout=3,
            ) as http:
                async with Client(
                    streamable_http_client(self.url, http_client=http), read_timeout_seconds=3
                ) as peer:
                    validate_listing(await peer.list_tools())
                    meta = (
                        TypeAdapter(types.RequestParamsMeta).validate_python(
                            {"mcp-agent-server/idempotency-key": key}
                        )
                        if key
                        else None
                    )
                    # Exactly one dispatch. The high-level helper can re-list/resend;
                    # a lost write response must never cause automatic re-execution.
                    try:
                        result = await peer.session.call_tool(tool, arguments, meta=meta)
                    except MCPError as exc:
                        if tool == "write_note" and _binding_conflict(exc):
                            raise DeniedKeyConflict from None
                        raise
                    if result.is_error:
                        raise ValueError("Unconfirmed internal tool result")
                    value = SPECS[tool].result.model_validate(
                        result.structured_content, strict=True
                    )
                    confirmed = {
                        "result": value.model_dump(mode="json"),
                        "replayed": bool(
                            result.meta and result.meta.get("mcp-agent-server/replayed")
                        ),
                    }
        except Exception:
            if confirmed is None:
                raise
            # A validated reply is issued only after durable post-audit. A later
            # transport-close error cannot erase that evidence. Never catch cancellation
            # or turn an unobserved reply into success; never log exception payloads.
            logging.getLogger(LOGGER).warning("Internal MCP cleanup failed after confirmed result")
        finally:
            # Tokens issued for one call are never retained or returned to a browser.
            self.clients.revoke_token(token)
        assert confirmed is not None
        return confirmed
