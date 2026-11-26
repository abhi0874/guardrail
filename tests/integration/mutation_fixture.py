"""Test-only mutation and process-crash fixture. Never imported by the server."""

import asyncio
import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from uuid import UUID

from mcp.server import MCPServer
from pydantic import BaseModel, ConfigDict

from mcp_agent_server.audit.storage import AuditStore
from mcp_agent_server.guardrails.authorization import LOCAL, AuthorizationContext
from mcp_agent_server.guardrails.middleware import ToolMiddleware
from mcp_agent_server.guardrails.models import GuardrailExecution, GuardrailRequest
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.guardrails.policy import Policy, parse_policy
from mcp_agent_server.idempotency.models import Mutation
from mcp_agent_server.storage.connection import Connection


class Increment(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    amount: int = 1


def fixture_policy(*, approval: bool = True, action: str = "permit") -> Policy:
    return parse_policy(
        json.dumps(
            {
                "schema_version": "1",
                "default_action": "deny",
                "rules": [
                    {
                        "tool": "increment",
                        "action": action,
                        "approval_required": approval,
                        "principals": ["local-anonymous", "operator"],
                        "roles": [],
                        "constraints": [
                            {"op": "integer_range", "field": "amount", "minimum": 1, "maximum": 5}
                        ],
                    }
                ],
            }
        ).encode()
    )


def increment(db: Connection, amount: int) -> dict[str, int]:
    # Test database header is transactional, persists on reopen and needs no extra schema.
    count = int(db.execute("PRAGMA application_id").fetchone()[0]) + amount
    db.execute(f"PRAGMA application_id={count:d}")
    return {"count": count}


class Fixture:
    def __init__(
        self, path: Path, connection: UUID, *, policy: Policy | None = None, seconds: float = 5.0
    ):
        self.store = AuditStore(path)
        self.pipe = Pipeline(
            self.store,
            {"increment": Increment},
            2048,
            5,
            policy=policy or fixture_policy(),
            mutations={"increment": Mutation(("count",), seconds)},
        )
        self.conn = connection
        self.calls = 0

    def approve(self) -> None:
        assert self.pipe.approvals
        self.pipe.approvals.issue(
            AuthorizationContext(identity=LOCAL, connection_id=self.conn),
            "increment",
            Increment(),
            issuer="fixture",
            ttl_seconds=120,
        )

    def request(self, amount: int = 1) -> GuardrailRequest:
        return GuardrailRequest(
            connection_id=self.conn, tool_name="increment", arguments={"amount": amount}
        )

    async def handler(self, data: BaseModel) -> dict[str, object]:
        self.pipe.claim("increment")
        self.calls += 1
        assert isinstance(data, Increment) and self.pipe.mutation_service is not None
        receipt = await self.pipe.mutation_service.local_effect(
            lambda db: increment(db, data.amount)
        )
        return {
            "structuredContent": receipt,
            "content": [{"type": "text", "text": "private-debug"}],
        }

    async def call(self, amount: int = 1) -> tuple[GuardrailExecution, dict[str, object] | None]:
        return await self.pipe.execute(
            self.request(amount), self.handler, idempotency_key="sample-key"
        )

    def count(self) -> int:
        with self.store.transaction() as db:
            return int(db.execute("PRAGMA application_id").fetchone()[0])


def serve(path: Path) -> None:
    from uuid import uuid4

    fixture = Fixture(path, uuid4())
    middleware = ToolMiddleware(
        fixture.pipe, server_info=lambda: {"name": server.name, "version": server.version}
    )
    server: MCPServer[None] = MCPServer("fixture", middleware=[middleware])

    @server.tool(structured_output=True)
    async def increment(amount: int = 1) -> dict[str, int]:
        """Increment the isolated test database counter."""
        raw = await fixture.handler(Increment(amount=amount))
        receipt = raw["structuredContent"]
        assert isinstance(receipt, dict)
        return receipt

    server.run(transport="stdio")


async def crash_worker(path: Path, conn: UUID, mode: str) -> None:
    fixture = Fixture(path, conn)
    assert fixture.pipe.mutation_service is not None
    if mode == "before":

        def die(op: str) -> None:
            os._exit(73)

        fixture.pipe.mutation_service.store.start = die  # type: ignore[method-assign]

    async def dispatch(data: BaseModel) -> dict[str, object]:
        if mode == "external":
            # A separate SQLite database stands in for an independently committed resource.
            fixture.pipe.claim("increment")
            with closing(sqlite3.connect(path.with_name("resource.sqlite3"))) as db, db:
                db.execute("CREATE TABLE IF NOT EXISTS delivered(value INTEGER)")
                db.execute("INSERT INTO delivered VALUES (1)")
            os._exit(75)
        result = await fixture.handler(data)
        if mode == "after":
            os._exit(74)
        return result

    execution, result = await fixture.pipe.execute(
        fixture.request(), dispatch, idempotency_key="sample-key"
    )
    assert execution.error is None and result
    print(json.dumps(result))


if __name__ == "__main__":
    asyncio.run(crash_worker(Path(sys.argv[1]), UUID(sys.argv[2]), sys.argv[3]))
