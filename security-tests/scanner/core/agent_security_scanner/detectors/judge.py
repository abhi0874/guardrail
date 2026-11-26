"""Injectable local-only judge, advisory only; never fabricates factual evidence."""

import asyncio
import json
from dataclasses import dataclass
from typing import Protocol


class JudgeClient(Protocol):
    """Implement with an in-process model or guarded localhost client, never cloud."""

    async def assess(self, payload: str) -> str: ...


@dataclass(frozen=True)
class JudgeOptions:
    enabled: bool = False
    timeout: float = 0.5
    retries: int = 2
    max_bytes: int = 8192

    def __post_init__(self) -> None:
        if (
            not 0 < self.timeout <= 30
            or not 0 <= self.retries <= 3
            or not 1 <= self.max_bytes <= 65536
        ):
            raise ValueError("Invalid bounded judge configuration")


async def consult(
    client: JudgeClient | None, payload: str, options: JudgeOptions
) -> tuple[str | None, str | None]:
    if client is None:
        return None, "judge_unavailable"
    if len(payload.encode()) > options.max_bytes:
        return None, "judge_input_limit"
    for attempt in range(options.retries + 1):
        try:
            async with asyncio.timeout(options.timeout):
                raw = await client.assess(payload)
            if len(raw.encode()) > options.max_bytes:
                raise ValueError("Output limit")
            answer = json.loads(raw)
            if not isinstance(answer, dict) or set(answer) != {"verdict", "explanation"}:
                raise ValueError("Schema mismatch")
            if (
                answer["verdict"] not in {"SUCCESS", "BLOCKED_OR_NOT_OBSERVED", "INDETERMINATE"}
                or not isinstance(answer["explanation"], str)
                or not 1 <= len(answer["explanation"]) <= 1000
            ):
                raise ValueError("Invalid judge answer")
            return raw, "advisory_only_missing_evidence_cannot_be_resolved"
        except Exception:
            if attempt < options.retries:
                await asyncio.sleep(min(0.01 * 2**attempt, 0.04))
    return None, "judge_failed_after_retries"
