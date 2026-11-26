import asyncio
from dataclasses import fields

from agent_security_scanner.detectors.engine import detect
from agent_security_scanner.detectors.models import DetectorInput, Verdict
from test_detector_rules import case


def test_engine_and_no_labels():
    result = asyncio.run(detect(case()))
    assert result.verdict == Verdict.SUCCESS and result.judge_outcome is None
    assert result.rule_outcomes[result.findings[0].rule_id] == Verdict.SUCCESS
    assert not {"label", "split", "id", "expected", "score"} & {
        f.name for f in fields(DetectorInput)
    }
