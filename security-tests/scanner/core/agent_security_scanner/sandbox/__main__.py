"""Safe local smoke query."""

import argparse
import asyncio
import json
from dataclasses import asdict

from agent_security_scanner.contracts import AgentRequest, ExecutionOutcome
from agent_security_scanner.sandbox.agent import SandboxAdapter


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true", required=True)
    parser.parse_args()
    result = asyncio.run(SandboxAdapter().execute(AgentRequest("smoke-1", "library opens")))
    print(json.dumps(asdict(result), allow_nan=False))
    raise SystemExit(0 if result.outcome == ExecutionOutcome.SUCCESS else 1)


if __name__ == "__main__":
    main()
