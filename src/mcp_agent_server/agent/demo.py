"""Recruiter-friendly offline walkthrough. Replay imports no live provider/client."""

import json
from pathlib import Path

from .recording import Recording, replay, save

FILES = ("search-read.json", "note.json", "message.json", "unauthorized.json")


def playback(directory: Path) -> str:
    # Deliberately fixed filenames, bounded allowlisted recordings, no command interpreter.
    rows = [replay(directory / name) for name in FILES]
    return "\n".join(
        f"Recorded {name}: {r.reason}; {len(r.events)} events"
        for name, r in zip(FILES, rows, strict=True)
    )


async def execute(output: Path | None = None) -> int:
    import sqlite3
    from contextlib import closing
    from tempfile import TemporaryDirectory, TemporaryFile, mkdtemp

    from ..config import AUDIT_ROOT
    from .connection import connect
    from .fake import FakeLLM, scenario
    from .runner import run

    AUDIT_ROOT.mkdir(parents=True, exist_ok=True)
    if output is None:
        base = Path(".runtime")
        base.mkdir(mode=0o700, exist_ok=True)
        output = Path(mkdtemp(prefix="offline-demo-", dir=base))
    else:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    print("OFFLINE MCP SECURITY DEMO — synthetic data, FakeLLM, no paid services")
    recordings: list[Recording] = []
    with (
        TemporaryDirectory(prefix="demo-", dir=AUDIT_ROOT) as temporary,
        TemporaryFile(mode="w+") as log,
    ):
        database = Path(temporary) / "demo.sqlite3"
        print("[1] Starting a disposable MCP server over real stdio")
        async with connect(audit_db=database, isolated=True, errlog=log) as client:
            tools = sorted(t.name for t in (await client.list_tools()).tools)
            expected = [
                "fetch_url",
                "health",
                "read_document",
                "search_documents",
                "send_message",
                "write_note",
            ]
            if tools != expected:
                raise RuntimeError("Unexpected production tool set")
            print("[2] Six production tools: " + ", ".join(tools))
            result = await run(client, scenario("search-read"), "Run the synthetic demonstration.")
            if result.recording.reason != "complete" or [
                e.tool for e in result.recording.events
            ] != ["search_documents", "read_document"]:
                raise RuntimeError("Search/read demonstration failed")
            recordings.append(result.recording)
            print("[3] Searched local documents and read approval-guide through MCP")
            note = json.dumps(
                {
                    "calls": [
                        {
                            "name": "write_note",
                            "arguments": {
                                "title": "Offline demo",
                                "body": "Synthetic demonstration note.",
                            },
                        }
                    ]
                }
            )
            result = await run(
                client,
                FakeLLM([note, note, '{"content":"Synthetic demonstration complete."}']),
                "Run the synthetic demonstration.",
                allow_writes=frozenset({"write_note"}),
            )
            if result.recording.reason != "complete" or [
                e.replayed for e in result.recording.events
            ] != [False, True]:
                raise RuntimeError("Idempotency demonstration failed")
            recordings.append(result.recording)
            print("[4] Two identical note requests; one committed note, second receipt replayed")
            result = await run(
                client,
                scenario("message"),
                "Run the synthetic demonstration.",
                allow_writes=frozenset({"send_message"}),
            )
            if result.recording.events[-1].code != "approval_required":
                raise RuntimeError("Approval boundary failed")
            recordings.append(result.recording)
            print("[5] Simulated message blocked: approval_required; only an operator may grant it")
            blocked = json.dumps(
                {
                    "calls": [
                        {"name": "read_document", "arguments": {"document_id": "restricted-doc"}}
                    ]
                }
            )
            result = await run(client, FakeLLM([blocked]), "Run the synthetic demonstration.")
            if (
                result.recording.reason != "tool_error"
                or result.recording.events[-1].code != "document_not_found"
            ):
                raise RuntimeError("Authorization demonstration failed")
            recordings.append(result.recording)
            print(
                "[6] Unauthorized document access denied by the server; correlated audit retained"
            )
        with closing(sqlite3.connect(database)) as db:
            counts = db.execute(
                "select (select count(*) from notes),(select count(*) from operations),"
                "(select count(*) from approvals where consumed_at is not null)"
            ).fetchone()
            if counts != (1, 1, 0):
                raise RuntimeError("Unexpected physical demo effects")
        for name, record in zip(FILES, recordings, strict=True):
            save(output / name, record)
        print("[7] Passive recording playback (server stopped; no model, tool or network dispatch)")
        print(playback(output))
        with closing(sqlite3.connect(database)) as db:
            after = db.execute(
                "select (select count(*) from notes),(select count(*) from operations),"
                "(select count(*) from approvals where consumed_at is not null)"
            ).fetchone()
        if after != counts:
            raise RuntimeError("Replay changed effects")
        log.seek(0)
        if "--- Logging error ---" in log.read():
            raise RuntimeError("Unexpected logging error")
    print("Gemini requests: 0 | Ollama requests: 0 | Replay tool calls: 0 | Replay mutations: 0")
    print("Sanitized recordings: " + str(output))
    return 0
