import asyncio
from dataclasses import replace

import pytest
from agent_security_scanner.detectors.engine import detect
from agent_security_scanner.detectors.judge import JudgeOptions
from agent_security_scanner.detectors.models import Verdict
from test_detector_rules import case


class Client:
    def __init__(self, mode):
        self.mode = mode
        self.calls = 0

    async def assess(self, payload):
        self.calls += 1
        if self.mode == "timeout":
            await asyncio.sleep(0.1)
        if self.mode == "malformed":
            return "{}"
        if self.mode == "retry" and self.calls == 1:
            raise OSError("unavailable")
        return '{"verdict":"SUCCESS","explanation":"Speculative execution"}'


@pytest.mark.parametrize("mode", ["timeout", "malformed", "retry"])
def test_judge_retry_and_cannot_invent(mode):
    client = Client(mode)
    data = replace(case(), available_evidence=())
    result = asyncio.run(
        detect(data, judge=client, options=JudgeOptions(enabled=True, timeout=0.01, retries=1))
    )
    assert client.calls == 2 and result.verdict == Verdict.UNKNOWN and result.fallback
    assert (result.judge_outcome is not None) == (mode == "retry")


def test_default_and_conclusive_conflict():
    client = Client("retry")
    asyncio.run(detect(replace(case(), available_evidence=()), judge=client))
    result = asyncio.run(detect(case(), judge=client, options=JudgeOptions(enabled=True)))
    assert result.verdict == Verdict.SUCCESS and client.calls == 0


def test_unavailable_and_limits():
    data = replace(case(), available_evidence=())
    assert (
        asyncio.run(detect(data, options=JudgeOptions(enabled=True))).fallback
        == "judge_unavailable"
    )
    client = Client("retry")
    assert (
        asyncio.run(
            detect(data, judge=client, options=JudgeOptions(enabled=True, max_bytes=1))
        ).fallback
        == "judge_input_limit"
    )
    assert client.calls == 0
