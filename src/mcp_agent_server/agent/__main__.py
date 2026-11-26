"""Run the standalone agent or display a passive recording."""

import argparse
import asyncio
import os
import sys
from contextlib import nullcontext
from pathlib import Path

from .recording import replay, reserve


async def live(args: argparse.Namespace) -> int:
    from .connection import connect
    from .fake import scenario
    from .models import LLMClient
    from .ollama import Ollama
    from .runner import run

    provider: LLMClient
    from collections.abc import Callable

    counters: Callable[[], dict[str, int]] | None = None
    if args.provider == "gemini":
        if not args.gemini_live:
            raise ValueError("Gemini requires explicit live opt-in")
        from .gemini import Gemini, GeminiConfig

        provider = Gemini(
            GeminiConfig(
                model=args.gemini_model or os.environ.get("GEMINI_MODEL", ""),
                enabled=True,
                requests=args.gemini_max_requests,
            )
        )
        gemini_provider = provider

        def gemini_counts() -> dict[str, int]:
            return gemini_provider.counters.model_dump()

        counters = gemini_counts
    elif args.provider == "ollama":
        provider = Ollama(os.environ.get("OLLAMA_MODEL", ""))
    else:
        provider = scenario(args.scenario)
    with reserve(args.record) if args.record else nullcontext(None) as finalize:
        async with (
            asyncio.timeout(30),
            connect(credential=args.credential, port=args.port) as client,
        ):
            outcome = await run(
                client, provider, args.prompt, allow_writes=frozenset(args.allow_write)
            )
        if finalize is not None:
            try:
                finalize(outcome.recording)
            except (OSError, ValueError):
                print(
                    "Recording finalization failed after execution. Effects may have committed; "
                    "inspect the server audit before retrying.",
                    file=sys.stderr,
                )
                print(outcome.recording.model_dump_json())
                return 2
    # Print the client-visible answer as JSON-escaped data.
    import json

    print(
        json.dumps(
            {
                "answer": outcome.answer,
                "recording": outcome.recording.model_dump(mode="json"),
                "requests": counters() if counters else None,
            },
            ensure_ascii=True,
        )
    )
    return 0 if outcome.recording.reason == "complete" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    playback_parser = commands.add_parser("replay")
    playback_parser.add_argument("file", type=Path)
    demo = commands.add_parser("demo")
    demo.add_argument("--output", type=Path)
    passive = commands.add_parser("demo-replay")
    passive.add_argument("directory", type=Path)
    start = commands.add_parser("run")
    start.add_argument("--provider", choices=["fake", "ollama", "gemini"], default="fake")
    start.add_argument("--gemini-live", action="store_true")
    start.add_argument("--gemini-model")
    start.add_argument("--gemini-max-requests", type=int, default=3)
    start.add_argument("--scenario", default="search-read")
    start.add_argument("--prompt", default="Run the synthetic demonstration.")
    start.add_argument(
        "--allow-write", choices=["write_note", "send_message"], action="append", default=[]
    )
    start.add_argument("--credential", type=Path)
    start.add_argument("--port", type=int, default=8765)
    start.add_argument("--record", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "replay":
            print(replay(args.file).model_dump_json(indent=2))
            return 0
        if args.command == "demo":
            from .demo import execute

            return asyncio.run(execute(args.output))
        if args.command == "demo-replay":
            from .demo import playback

            print(playback(args.directory))
            return 0
        return asyncio.run(live(args))
    except Exception:
        print("Agent configuration, connection or recording failed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
