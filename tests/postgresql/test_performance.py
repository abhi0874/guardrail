"""Measured local PostgreSQL MCP workloads. No timing threshold is a flaky test gate."""

import asyncio
import json
import platform
from math import ceil
from pathlib import Path
from time import perf_counter_ns

import pytest
from integration.http_support import client, listener
from integration.test_production_tools import key

from mcp_agent_server.config import Settings
from mcp_agent_server.guardrails.approval import ApprovalGate
from mcp_agent_server.guardrails.policy import load_policy
from mcp_agent_server.storage.postgres import PostgresStore
from mcp_agent_server.tools.models import Message


def summary(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {f"p{q}_ms": ordered[ceil(len(ordered) * q / 100) - 1] for q in (50, 95, 99)}


@pytest.mark.asyncio
async def test_measured_postgres_workloads(
    pg_store: PostgresStore, pg_settings: Settings, audit_db: Path
) -> None:
    samples: dict[str, list[float]] = {
        name: []
        for name in (
            "health",
            "search_documents",
            "read_document",
            "write_note",
            "idempotency_replay",
            "send_message",
            "database_transaction",
        )
    }
    trials = []
    total_start = perf_counter_ns()
    async with listener(
        audit_db, storage_backend="postgresql", database_url=pg_settings.database_url
    ) as (url, clients, _):
        for trial in range(3):
            token, reference = clients.issue()
            async with client(url, token) as peer:
                await peer.list_tools()
                seed = {"title": "Replay seed", "body": "Persistent"}
                await peer.call_tool("write_note", seed, meta=key(f"benchmark-replay-{trial}"))
                # Warm the read path in each trial; setup/approvals outside samples.
                await peer.call_tool("health")
                trial_start = perf_counter_ns()
                for category in tuple(samples)[:-1]:
                    gate = ApprovalGate(pg_store, load_policy())
                    messages = [
                        Message(
                            recipient="ops-lab",
                            subject="Measured simulation",
                            body=f"Trial {trial} operation {i}",
                        )
                        for i in range(8)
                    ]
                    if category == "send_message":
                        for message in messages:
                            gate.issue(
                                reference.authorization,
                                "send_message",
                                message,
                                issuer="benchmark",
                                ttl_seconds=120,
                            )
                    semaphore = asyncio.Semaphore(2)

                    async def call(
                        i: int,
                        category: str = category,
                        trial: int = trial,
                        semaphore: asyncio.Semaphore = semaphore,
                        messages: list[Message] = messages,
                        seed: dict[str, str] = seed,
                    ) -> None:
                        async with semaphore:
                            started = perf_counter_ns()
                            if category == "idempotency_replay":
                                result = await peer.call_tool(
                                    "write_note", seed, meta=key(f"benchmark-replay-{trial}")
                                )
                                assert (
                                    result.meta and result.meta["mcp-agent-server/replayed"] is True
                                )
                            elif category == "write_note":
                                result = await peer.call_tool(
                                    category,
                                    {
                                        "title": "Measured note",
                                        "body": f"Trial {trial} operation {i}",
                                    },
                                    meta=key(f"bench-note-{trial}-{i}"),
                                )
                            elif category == "send_message":
                                result = await peer.call_tool(
                                    category,
                                    messages[i].model_dump(),
                                    meta=key(f"bench-message-{trial}-{i}"),
                                )
                            else:
                                arguments = (
                                    {"query": "approval"}
                                    if category == "search_documents"
                                    else {"document_id": "approval-guide"}
                                    if category == "read_document"
                                    else {}
                                )
                                result = await peer.call_tool(category, arguments)
                            samples[category].append((perf_counter_ns() - started) / 1e6)
                            assert not result.is_error and result.structured_content

                    await asyncio.gather(*(call(i) for i in range(8)))
                trials.append(
                    {
                        "trial": trial,
                        "operations": 48,
                        "duration_ms": (perf_counter_ns() - trial_start) / 1e6,
                    }
                )
    for _ in range(24):
        started = perf_counter_ns()
        with pg_store.transaction() as db:
            assert db.execute("SELECT 1").fetchone()[0] == 1
        samples["database_transaction"].append((perf_counter_ns() - started) / 1e6)
    with pg_store.transaction() as db:
        effects = {
            "notes": db.execute("SELECT count(*) FROM notes").fetchone()[0],
            "simulations": db.execute("SELECT count(*) FROM simulations").fetchone()[0],
            "consumed_approvals": db.execute(
                "SELECT count(*) FROM approvals WHERE consumed_at IS NOT NULL"
            ).fetchone()[0],
        }
    assert effects == {"notes": 27, "simulations": 24, "consumed_approvals": 24}
    assert all(len(values) == 24 for values in samples.values())
    report = {
        "schema_version": 1,
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "database": "PostgreSQL 17 in local Docker; no hosted/network-region measurement",
        },
        "workload": {
            "trials": 3,
            "requests_per_category_per_trial": 8,
            "bounded_concurrency": 2,
            "pool_size": 2,
            "percentiles": "nearest-rank; approval preparation excluded from request samples",
            "network": "loopback only",
            "full_workload_ms": (perf_counter_ns() - total_start) / 1e6,
        },
        "trials": trials,
        "samples_ms": samples,
        "summary": {name: summary(values) for name, values in samples.items()},
        "observed_effects": effects,
    }
    destination = Path(".cache/cloud-phase1/postgres-benchmark.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n")
    assert sum(t["operations"] for t in trials) == 144
