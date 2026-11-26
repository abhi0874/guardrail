"""Bounded JSON projection shared by tool and future resource adapters."""

import json
import logging
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from mcp_agent_server.errors import ErrorCode, GuardrailError
from mcp_agent_server.logging import LOGGER

from .content_screening import Disposition, screen
from .security_settings import OutputSettings

MARKER = "[REDACTED]"
_PATTERNS = {
    "provider-key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}"),
    "bearer": re.compile(r"\bBearer[ \t]+[A-Za-z0-9._~+/-]{8,}=*", re.I),
    "aws-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
}
_DISPLAY = frozenset({"title", "snippet", "content", "text"})


def compact(data: object) -> str:
    return json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


@dataclass
class Findings:
    source: str
    rules: set[str] = field(default_factory=set)
    masks: int = 0
    screening: Disposition = Disposition.ALLOW

    def metadata(self) -> dict[str, object]:
        return {
            "source": self.source,
            "profile": "v1",
            "disposition": self.screening.value,
            "rules": sorted(self.rules),
            "redactions": self.masks,
        }


class OutputGuard:
    def __init__(
        self, settings: OutputSettings, schemas: Mapping[str, type[BaseModel]] | None = None
    ):
        self.settings = settings
        self.schemas = dict(schemas or {})
        self.literals = tuple(x.get_secret_value() for x in settings.literals)

    def _mask(self, text: str, report: Findings) -> str:
        # Store one interval per input position, even with overlapping configured matches.
        ends: dict[int, int] = {}
        for token in self.literals:
            pos = text.find(token)
            while pos != -1:
                ends[pos] = max(ends.get(pos, 0), pos + len(token))
                report.rules.add("literal")
                pos = text.find(token, pos + 1)
        for rule in self.settings.patterns:
            for match in _PATTERNS[rule].finditer(text):
                ends[match.start()] = max(ends.get(match.start(), 0), match.end())
                report.rules.add(rule)
        if not ends:
            return text
        pieces: list[str] = []
        end = 0
        for start, stop in sorted(ends.items()):
            if start >= end:
                pieces.extend((text[end:start], MARKER))
                report.masks += 1
            end = max(stop, end)
        pieces.append(text[end:])
        result = "".join(pieces)
        if any(token in result for token in self.literals):
            raise GuardrailError(ErrorCode.OUTPUT_UNSAFE)
        return result

    def process(self, value: object, source: str, *, tool: bool = False) -> tuple[object, Findings]:
        return self._process(value, source, tool=tool, inspect_content=True)

    def _process(
        self, value: object, source: str, *, tool: bool, inspect_content: bool
    ) -> tuple[object, Findings]:
        report = Findings(source)
        items = 0
        budget = self.settings.max_bytes

        def visit(node: object, depth: int, key: str = "") -> Any:
            nonlocal items, budget
            items += 1
            if depth > self.settings.max_depth or items > self.settings.max_items:
                raise GuardrailError(ErrorCode.OUTPUT_LIMIT)
            if type(node) is str:
                if len(node) > min(self.settings.max_text, budget):
                    raise GuardrailError(ErrorCode.OUTPUT_LIMIT)
                size = len(node.encode())
                budget -= size
                if size > self.settings.max_text or budget < 0:
                    raise GuardrailError(ErrorCode.OUTPUT_LIMIT)
                if not inspect_content:
                    return node
                finding = screen(node, source)
                report.rules.update(finding.rules)
                if finding.disposition is Disposition.BLOCK:
                    raise GuardrailError(ErrorCode.OUTPUT_BLOCKED)
                if finding.rules:
                    report.screening = Disposition.WARN
                text = self._mask(node, report)
                if text != node and (key == "<key>" or tool and key not in _DISPLAY):
                    raise GuardrailError(ErrorCode.OUTPUT_UNSAFE)
                if len(text.encode()) > self.settings.max_text:
                    raise GuardrailError(ErrorCode.OUTPUT_LIMIT)
                return text
            if isinstance(node, (dict, list)):
                if len(node) > self.settings.max_items - items:
                    raise GuardrailError(ErrorCode.OUTPUT_LIMIT)
                if isinstance(node, list):
                    return [visit(x, depth + 1, key) for x in node]
                result = {}
                for k, v in node.items():
                    if type(k) is not str:
                        raise GuardrailError(ErrorCode.OUTPUT_UNSAFE)
                    visit(k, depth + 1, "<key>")
                    result[k] = visit(v, depth + 1, k)
                return result
            if (
                node is None
                or type(node) is bool
                or type(node) is int
                and node.bit_length() <= 64
                or type(node) is float
                and math.isfinite(node)
            ):
                return node
            raise GuardrailError(ErrorCode.OUTPUT_UNSAFE)

        try:
            clean = visit(value, 1)
            self.check_encoded(clean)
            return clean, report
        except GuardrailError:
            raise
        except Exception:
            raise GuardrailError(ErrorCode.OUTPUT_UNSAFE) from None

    def check_encoded(self, data: object) -> None:
        encoded = compact(data)
        if len(encoded.encode()) > self.settings.max_bytes:
            raise GuardrailError(ErrorCode.OUTPUT_LIMIT)
        if any(token in encoded for token in self.literals):
            raise GuardrailError(ErrorCode.OUTPUT_UNSAFE)

    def receipt(self, encoded: str, source: str) -> object:
        if len(encoded) > self.settings.max_bytes:
            raise GuardrailError(ErrorCode.OUTPUT_LIMIT)
        clean, _ = self.process(json.loads(encoded), source, tool=True)
        return clean

    def render(
        self,
        source: str,
        raw: object,
        replay: bool | None,
        stamp: dict[str, object] | None,
        modern: bool,
    ) -> dict[str, object]:
        try:
            clean, report = self.process(raw, source, tool=True)
            if schema := self.schemas.get(source):
                schema.model_validate(clean, strict=True)
            meta: dict[str, object] = {"mcp-agent-server/output": report.metadata()}
            if replay is not None:
                meta["mcp-agent-server/replayed"] = replay
            if stamp is not None:
                from mcp_types import SERVER_INFO_META_KEY

                self.process(stamp, source, tool=True)
                meta[SERVER_INFO_META_KEY] = stamp
            result: dict[str, object] = {
                "structuredContent": clean,
                "content": [{"type": "text", "text": compact(clean)}],
                "_meta": meta,
            }
            if modern:
                result["resultType"] = "complete"
            # Already inspected fields are encoded once into the MCP text block.
            # Re-screening JSON escapes changes quotation context. Check the entire
            # envelope's bounds without classifying that generated encoding as new data.
            self._process(result, source, tool=True, inspect_content=False)
            self.check_encoded(result)
            if report.rules:
                logging.getLogger(LOGGER).info(
                    "Output rules %s; redactions %d", ",".join(sorted(report.rules)), report.masks
                )
            return result
        except GuardrailError:
            raise
        except Exception:
            raise GuardrailError(ErrorCode.OUTPUT_UNSAFE) from None

    def error_message(self, text: str) -> str:
        try:
            safe, _ = self.process(text, "error")
            return str(safe)
        except Exception:
            return ""


Render = Callable[[str, object, bool | None], dict[str, object]]
