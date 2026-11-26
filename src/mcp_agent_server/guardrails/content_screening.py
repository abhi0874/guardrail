"""Version 1 deterministic rules. Content is data and has no authority."""

import re
from dataclasses import dataclass
from enum import StrEnum

from mcp_agent_server.errors import ErrorCode, GuardrailError


class Disposition(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class Screening:
    source: str
    disposition: Disposition
    rules: tuple[str, ...]
    version: str = "v1"

    @property
    def explanation(self) -> str:
        return {
            Disposition.ALLOW: "No configured instruction rule matched.",
            Disposition.WARN: "Potential instructions appear in ambiguous or explanatory text.",
            Disposition.BLOCK: "A direct instruction matched a configured high-confidence rule.",
        }[self.disposition]


# Each pattern is fixed, local and bounded by the surrounding field budget.
_RULES = tuple(
    (name, re.compile(pattern, re.I))
    for name, pattern in (
        (
            "role-forgery",
            r"(?:<\|(?:im_start\|>\s*|)(?:system|developer)\b|\[(?:system|developer)\]"
            r"|</?(?:system|developer)>|(?:new )?(?:system|developer) message\s*:)",
        ),
        (
            "override",
            r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|earlier)"
            r"\s+(?:instructions|directions|rules)\b",
        ),
        (
            "prompt-disclosure",
            r"\b(?:reveal|print|disclose|show)\s+(?:the |your |all )?"
            r"(?:hidden prompts?|system prompts?|secrets?|credentials)\b",
        ),
        (
            "policy-bypass",
            r"\b(?:ignore|bypass|disable|skip)\s+(?:the |all |required )?"
            r"(?:security policy|approval(?: requirements?)?|authorization)\b",
        ),
        (
            "privilege-grant",
            r"\bgrant\s+(?:yourself|me|the agent)\s+(?:admin|administrator|root)\b",
        ),
        (
            "tool-redirection",
            r"\b(?:call|invoke|execute)\s+(?:the |an? )?"
            r"(?:unauthorized|forbidden|unapproved) tool\b",
        ),
        (
            "exfiltration",
            r"\b(?:exfiltrate|send|upload)\s+(?:the |all |your )?"
            r"(?:secrets?|credentials?|tokens?|canary)\s+to\b",
        ),
    )
)


def screen(text: str, source: str) -> Screening:
    if len(text) > 262144:
        raise GuardrailError(ErrorCode.OUTPUT_LIMIT)
    found: set[str] = set()
    block = False
    for line in text.splitlines():
        # Recognize closed inline quotations without treating a magic word like
        # "example" as authority. Mark quoted character positions in one bounded pass.
        quoted = bytearray(len(line))
        for quote in re.finditer(r""""[^"\n]*"|'[^'\n]*'|`[^`\n]*`""", line):
            quoted[quote.start() : quote.end()] = b"1" * (quote.end() - quote.start())
        for name, rule in _RULES:
            for hit in rule.finditer(line):
                found.add(name)
                # Quoted or explanatory mentions warn. A directive at a sentence boundary
                # is stronger evidence. An isolated override phrase still only warns.
                before = hit.start() - 1
                while before >= 0 and line[before].isspace():
                    before -= 1
                imperative = (before < 0 or line[before] in ".!:;") and not quoted[hit.start()]
                imperative = imperative and not line.lstrip().startswith(">")
                if imperative and (name != "override" or re.search(r"[^ .!:;]", line[hit.end() :])):
                    block = True
    disposition = Disposition.BLOCK if block else Disposition.WARN if found else Disposition.ALLOW
    return Screening(source, disposition, tuple(sorted(found)))
