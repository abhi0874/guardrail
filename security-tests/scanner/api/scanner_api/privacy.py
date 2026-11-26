"""Fail closed on sensitive evidence; never silently redact an observed effect."""

import html
import json
import re
from typing import Any

RULES = {
    "private absolute path": r"(?i)(/(?:Users|home|private|Volumes|etc|var|tmp)/|\b[A-Z]:[\\/])",
    "private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "provider credential": (
        r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|AKIA[A-Z0-9]{16}|"
        r"gh[pousr]_[A-Za-z0-9]{30,})"
    ),
    "connection string": r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://",
    "authorization value": r"(?i)(?:bearer\s+[A-Za-z0-9._-]{12,}|authorization\s*[:=])",
    "credential assignment": (
        r"(?i)(?:api[_-]?key|password|client[_-]?secret|access[_-]?token)"
        r"\s*[\"']?\s*[:=]\s*[\"']?[^\s\"']{8,}"
    ),
    "original source snapshot": (
        r"(?i)(nextjs_target_reference|reference-rag-agent|[a-z0-9_-]+-docrag|"
        r"rag-answer\.ts|validated-stream\.ts)"
    ),
}


def audit(value: Any) -> None:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    decoded = html.unescape(text).replace("\\/", "/")
    for label, pattern in RULES.items():
        if re.search(pattern, decoded):
            raise ValueError(f"Public-data audit rejected {label}; evidence was not redacted")
