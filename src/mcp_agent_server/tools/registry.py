"""Trusted production registrations. Every entry consumes a committed dispatch grant."""

import json
from dataclasses import dataclass

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel

from mcp_agent_server.adapters import documents
from mcp_agent_server.adapters.http import Fetcher
from mcp_agent_server.adapters.notes import insert_note
from mcp_agent_server.adapters.outbox import Outbox
from mcp_agent_server.guardrails.pipeline import Pipeline
from mcp_agent_server.guardrails.validation import HealthArguments
from mcp_agent_server.idempotency.models import Mutation
from mcp_agent_server.resilience.executor import ResilienceExecutor
from mcp_agent_server.resilience.models import Settings as DependencySettings

from .models import (
    Body,
    Document,
    DocumentId,
    Fetch,
    Health,
    Limit,
    Matches,
    Message,
    MessageReceipt,
    Note,
    NoteReceipt,
    Page,
    Query,
    Read,
    Recipient,
    Search,
    Title,
    UrlText,
)


class SimulationMutation(Mutation):
    """Extend the v3 receipt codec only for fixed-format IDs and synthetic recipient literals."""

    def encode(self, data: object) -> str:
        receipt = MessageReceipt.model_validate(data, strict=True)
        return json.dumps(receipt.model_dump(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class ToolSpec:
    arguments: type[BaseModel]
    result: type[BaseModel]
    mutation: Mutation | None = None
    requires_approval: bool = False
    network_dependency: bool = False

    @property
    def annotations(self) -> ToolAnnotations:
        return ToolAnnotations.model_validate(
            {"readOnlyHint": self.mutation is None, "openWorldHint": self.network_dependency}
        )


SPECS = {
    "health": ToolSpec(HealthArguments, Health),
    "search_documents": ToolSpec(Search, Matches),
    "read_document": ToolSpec(Read, Document),
    "write_note": ToolSpec(Note, NoteReceipt, Mutation(("note_id", "persisted"))),
    "send_message": ToolSpec(
        Message,
        MessageReceipt,
        SimulationMutation(("simulation_id", "recipient", "recorded_in_memory")),
        requires_approval=True,
    ),
    "fetch_url": ToolSpec(Fetch, Page, network_dependency=True),
}


def register(server: MCPServer[None], pipe: Pipeline, fetcher: Fetcher, outbox: Outbox) -> None:
    executor = ResilienceExecutor(pipe, {host: DependencySettings() for host in fetcher.hosts})

    @server.tool(structured_output=True, annotations=SPECS["search_documents"].annotations)
    async def search_documents(query: Query, limit: Limit = 3) -> Matches:
        """Search the local synthetic handbook by word, ordered by relevance."""
        with pipe.handler("search_documents"):
            return documents.search(query, limit)

    @server.tool(structured_output=True, annotations=SPECS["read_document"].annotations)
    async def read_document(document_id: DocumentId) -> Document:
        """Read one approved handbook document by ID."""
        with pipe.handler("read_document"):
            return documents.read(document_id)

    @server.tool(structured_output=True, annotations=SPECS["write_note"].annotations)
    async def write_note(title: Title, body: Body) -> NoteReceipt:
        """Persist a local synthetic note. Supply the idempotency key in request metadata."""
        with pipe.handler("write_note"):
            assert pipe.mutation_service
            receipt = await pipe.mutation_service.local_effect(
                lambda db: insert_note(db, title, body)
            )
            return NoteReceipt.model_validate(receipt)

    @server.tool(structured_output=True, annotations=SPECS["send_message"].annotations)
    async def send_message(recipient: Recipient, subject: Title, body: Body) -> MessageReceipt:
        """Record an approved simulation in memory. Requires an idempotency key in metadata."""
        with pipe.handler("send_message"):
            message = Message(recipient=recipient, subject=subject, body=body)
            from mcp_agent_server.storage.simulations import record

            return await record(pipe, outbox, message)

    @server.tool(structured_output=True, annotations=SPECS["fetch_url"].annotations)
    async def fetch_url(url: UrlText) -> Page:
        """Read bounded UTF-8 text from an approved public HTTPS host."""
        with pipe.handler("fetch_url"):
            return await fetcher.fetch(url, executor)
