import re

from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.tools.models import Document, Hit, Matches

# Immutable package data. An input ID never becomes a filesystem path.
CORPUS = (
    Document(
        document_id="stdio-guide",
        title="MCP stdio integration",
        category="integration",
        content="Use stdio for local MCP requests. Send diagnostics to stderr. List tools "
        "before calling a tool and check its structured result.",
    ),
    Document(
        document_id="retry-policy",
        title="Reliability and retry policy",
        category="reliability",
        content="Retry transient read failures within a total deadline. Writes require "
        "an idempotency key. A retry must never repeat an uncertain side effect.",
    ),
    Document(
        document_id="incident-runbook",
        title="Incident response runbook",
        category="operations",
        content="During an incident, inspect the audit request ID and original "
        "approval. Reconcile uncertain effects before issuing another write.",
    ),
    Document(
        document_id="approval-guide",
        title="Operator approval policy",
        category="security",
        content="An operator binds approval to validated arguments and a "
        "trusted connection. An approval authorizes one new simulated message.",
    ),
)


def read(document_id: str) -> Document:
    for doc in CORPUS:
        if doc.document_id == document_id:
            return doc
    raise GuardrailError(ErrorCode.DOCUMENT_NOT_FOUND)


def search(query: str, limit: int) -> Matches:
    words = set(re.findall(r"\w+", query.casefold()))
    ranked: list[tuple[int, str, Hit]] = []
    for doc in CORPUS:
        title = re.findall(r"\w+", doc.title.casefold())
        content = re.findall(r"\w+", doc.content.casefold())
        score = sum(3 * title.count(w) + content.count(w) for w in words)
        if score:
            ranked.append(
                (
                    -score,
                    doc.document_id,
                    Hit(
                        document_id=doc.document_id,
                        title=doc.title,
                        category=doc.category,
                        snippet=doc.content[:180],
                    ),
                )
            )
    ranked.sort(key=lambda item: (item[0], item[1]))
    return Matches(matches=[item[2] for item in ranked[:limit]])
