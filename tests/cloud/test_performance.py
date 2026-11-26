"""Matched local TCP ingress / private MCP / PostgreSQL measurements."""

import asyncio
import json
import platform
import socket
from math import ceil
from pathlib import Path
from time import perf_counter_ns

import httpx
import pytest
import uvicorn

from mcp_agent_server.cloud.app import CloudApplication
from mcp_agent_server.cloud.runtime import PrivateServer


def summary(values: list[float]) -> dict[str, float]:
    values = sorted(values)
    return {f"p{q}_ms": values[ceil(len(values) * q / 100) - 1] for q in (50, 95, 99)}


@pytest.mark.asyncio
async def test_warmed_ingress_latency(cloud_app: CloudApplication) -> None:
    samples: dict[str, list[float]] = {
        k: []
        for k in (
            "ingress_health",
            "private_mcp_health",
            "ingress_write_note",
            "ingress_replay",
            "postgres_transaction",
        )
    }
    overall = perf_counter_ns()
    trials = []
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server = PrivateServer(
            uvicorn.Config(
                cloud_app,
                host="127.0.0.1",
                port=port,
                proxy_headers=False,
                log_config=None,
                access_log=False,
                lifespan="off",
            )
        )
        task = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            async with asyncio.timeout(5):
                while not server.started:
                    await asyncio.sleep(0.01)
            async with httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{port}",
                trust_env=False,
                headers={
                    "Host": "demo.example.test",
                    "Origin": "https://demo.example.test",
                    "X-Forwarded-Proto": "https",
                    "Authorization": "Bearer " + "A" * 43,
                    "Content-Type": "application/json",
                },
            ) as api:
                for trial in range(3):
                    assert (await api.post("/api/v1/health", json={})).status_code == 200
                    start = perf_counter_ns()
                    semaphore = asyncio.Semaphore(2)

                    async def health(i: int, semaphore: asyncio.Semaphore = semaphore) -> None:
                        async with semaphore:
                            started = perf_counter_ns()
                            r = await api.post("/api/v1/health", json={})
                            samples["ingress_health"].append((perf_counter_ns() - started) / 1e6)
                            assert r.status_code == 200 and r.json()["outcome"] == "confirmed"

                    await asyncio.gather(*(health(i) for i in range(8)))
                    for _ in range(8):
                        started = perf_counter_ns()
                        private_result = await cloud_app.broker.call(
                            cloud_app.config.clients[0].identifier, "health", {}, None
                        )
                        samples["private_mcp_health"].append((perf_counter_ns() - started) / 1e6)
                        assert private_result["result"]
                    for i in range(3):
                        data = {
                            "title": "Measured cloud note",
                            "body": f"Trial {trial} operation {i}",
                        }
                        headers = {
                            "Authorization": "Bearer " + "B" * 43,
                            "Idempotency-Key": f"cloud-bench-{trial}-{i}",
                        }
                        for category in ("ingress_write_note", "ingress_replay"):
                            started = perf_counter_ns()
                            r = await api.post("/api/v1/write_note", json=data, headers=headers)
                            samples[category].append((perf_counter_ns() - started) / 1e6)
                            assert r.status_code == 200 and r.json()["replayed"] == (
                                category == "ingress_replay"
                            )
                    trials.append((perf_counter_ns() - start) / 1e6)
        finally:
            server.should_exit = True
            await task
    for _ in range(24):
        started = perf_counter_ns()
        with cloud_app.sessions.store.transaction() as db:
            assert db.execute("SELECT 1").fetchone()[0] == 1
        samples["postgres_transaction"].append((perf_counter_ns() - started) / 1e6)
    with cloud_app.sessions.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 9
        assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == 9
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 0
    result = {
        "schema_version": 1,
        "environment": platform.platform(),
        "conditions": {
            "trials": 3,
            "health_concurrency": 2,
            "write_concurrency": 1,
            "pool_size": 2,
            "public_health_samples": 24,
            "private_mcp_samples": 24,
            "write_samples": 9,
            "replay_samples": 9,
            "postgres_samples": 24,
            "hosting": "local only; hosted latency/cold-start unmeasured",
        },
        "samples_ms": samples,
        "percentiles": {k: summary(v) for k, v in samples.items()},
        "trial_workflow_ms": trials,
        "full_workflow_ms": (perf_counter_ns() - overall) / 1e6,
        "effects": {"notes": 9, "operations": 9, "approvals": 0},
        "percentile_method": "nearest-rank pooled samples; p99 is sample maximum",
    }
    path = Path(".cache/cloud-phase2/latency.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n")
