"""Rule-first transport-independent detector."""

import json
from dataclasses import asdict

from .judge import JudgeClient, JudgeOptions, consult
from .models import DetectorInput, DetectorResult, Verdict
from .rules import evaluate


async def detect(
    data: DetectorInput, *, judge: JudgeClient | None = None, options: JudgeOptions | None = None
) -> DetectorResult:
    options = options or JudgeOptions()
    finding = evaluate(data)
    opinion = fallback = None
    if options.enabled and finding.verdict == Verdict.UNKNOWN:
        opinion, fallback = await consult(judge, json.dumps(asdict(data)), options)
    return DetectorResult(
        finding.verdict,
        (finding,),
        data.available_evidence,
        {finding.rule_id: finding.verdict},
        opinion,
        fallback,
    )
