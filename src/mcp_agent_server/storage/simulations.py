"""Durable hosted simulation effects share their receipt transaction."""

from uuid import uuid4

from mcp_agent_server.adapters.outbox import Outbox
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.tools.models import Message, MessageReceipt

from .connection import Connection
from .postgres import PostgresStore


async def record(pipe: Pipeline, outbox: Outbox, message: Message) -> MessageReceipt:
    if not isinstance(pipe.audit, PostgresStore):
        return outbox.record(message)
    assert pipe.mutation_service is not None
    receipt = MessageReceipt(simulation_id=uuid4().hex, recipient=message.recipient)

    def effect(db: Connection) -> MessageReceipt:
        # The transaction owns the operation and only it can bind the local effect.
        owned = pipe.mutation_service
        assert owned is not None
        operation = owned.operation_id()
        db.execute(
            "INSERT INTO simulations VALUES (?,?,?,?,?)",
            (receipt.simulation_id, operation, message.recipient, message.subject, message.body),
        )
        return receipt

    value = await pipe.mutation_service.local_effect(effect)
    result = MessageReceipt.model_validate(value)
    outbox.entries.append((result, message))
    return result
