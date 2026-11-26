"""Render untrusted source strings as inert text, never Markdown/HTML instructions."""

import string
from typing import Any


def escape(value: object) -> str:
    # Entities cannot open tables, links, HTML, fences, blockquotes or auto-links.
    return "".join(
        f"&#{ord(c)};"
        if c in string.punctuation
        or c in "\r\n\t"
        or ord(c) < 32
        or 0x7F <= ord(c) <= 0x9F
        or 0x202A <= ord(c) <= 0x202E
        or 0x2066 <= ord(c) <= 0x2069
        else c
        for c in str(value)
    )


def render(report: dict[str, Any]) -> str:
    s = report["statistics"]
    p = report["provenance"]
    lines = [
        "# Agent Security Scanner — Security Assessment",
        "",
        "## Executive summary",
        "",
        f"**{s['submitted']} executed attacks · {s['observed_effects']} observed task-boundary "
        f"effects · {s['distinct_findings']} distinct findings · "
        f"{s['indeterminate']} indeterminate**",
        "",
        "Results describe the controlled synthetic sandbox, not a live assessment of the "
        "original Next.js RAG application.",
        "",
        f"Tested: {escape(p['scan_started_at'])} to {escape(p['scan_ended_at'])}. "
        f"Source status: {escape(p['source_status'])}.",
        "",
        f"Source run: {escape(report['source_scan_id'])}. Report generated: "
        f"{escape(report['generated_at'])}.",
        "",
        "## Assessment scope and methodology",
        "",
        "Read-only analysis of saved SQLite and JSON artifacts from isolated synthetic sandbox "
        "sessions. Tool invocations, results, task policy and before/after state must agree. "
        "No target is contacted during reporting. Confidence describes evidence strength; "
        "severity describes observed impact. Reproduction commands below are instructions, "
        "not claims of replay performed by this generator.",
        "",
        "## Scan coverage",
        "",
        "| Measure | Count |",
        "| --- | ---: |",
    ]
    for label, key in (
        ("Loaded definitions", "loaded"),
        ("Prepared", "prepared"),
        ("Submitted", "submitted"),
        ("Persisted", "persisted"),
        ("Trace events", "trace_events"),
        ("Successful executions", "successful_attack_executions"),
        ("Observed effects", "observed_effects"),
        ("Distinct findings", "distinct_findings"),
        ("Multi-attack findings", "multi_attack_findings"),
        ("Indeterminate", "indeterminate"),
        ("Unrecorded definitions", "unrecorded_definitions"),
    ):
        lines.append(f"| {label} | {s[key]} |")
    for status, count in sorted(s["statuses"].items()):
        lines.append(f"| {escape(status)} executions | {count} |")
    lines += [
        "",
        "## Findings at a glance",
        "",
        "Custom CVSS-inspired severity score (0–10), not official CVSS. "
        "No CVSS vectors are assigned. Findings are ranked by score, then stable identifier.",
        "",
        "| Finding | Tool/resource | Score | Band | Confidence | Effects |",
        "| --- | --- | ---: | --- | --- | ---: |",
    ]
    for f in report["findings"]:
        lines.append(
            f"| {escape(f['title'])} | {escape(f['tool'] + '/' + f['resource'])} | "
            f"{f['severity']['score']} | {f['severity']['band']} | {f['confidence']} | "
            f"{len(f['observations'])} |"
        )
    lines += [
        "",
        "Severity distribution: "
        + ", ".join(f"{b} {n}" for b, n in sorted(s["severity_distribution"].items()))
        + ".",
        "",
        "## Severity-ranked findings, evidence and reproduction",
        "",
    ]
    if not report["findings"]:
        lines += ["No supported confirmed findings in the recorded executions.", ""]
    for f in report["findings"]:
        lines += [
            f"### {escape(f['title'])}",
            "",
            f"ID: {escape(f['finding_id'])}. Categories: {escape(', '.join(f['categories']))}.",
            "",
            f"**{f['severity']['band']} — {f['severity']['score']}/10; "
            f"confidence {f['confidence']}.** {escape(f['confidence_rationale'])}",
            "",
            escape(f["grouping_rationale"]),
            "",
            escape(f["mechanism"]),
            "",
            "| Dimension | Value / maximum | Rationale |",
            "| --- | ---: | --- |",
        ]
        for d in f["severity"]["dimensions"]:
            lines.append(
                f"| {escape(d['name'])} | {d['value']} / {d['maximum']} | "
                f"{escape(d['rationale'])} |"
            )
        for o in f["observations"]:
            lines += [
                "",
                f"#### {escape(o['attack_id'])} — revision {o['revision']}",
                "",
                escape(o["effect"]),
                "",
                "Expected boundary: " + escape(o["expected_boundary"]),
                "",
                "| Artifact | JSON Pointer | Evidence |",
                "| --- | --- | --- |",
            ]
            for e in o["evidence"]:
                lines.append(
                    f"| {escape(e['artifact'])} | {escape(e['pointer'])} | {escape(e['purpose'])} |"
                )
            lines += [
                "",
                "Replay from repository root:",
                "",
                escape(o["reproduction"]),
                "",
                "Expected current effect: " + escape(o["effect"]),
                "",
                "Expected fixed behavior: " + escape(o["expected_fixed_behavior"]),
                "",
            ]
        r = f["recommendation"]
        lines += ["Proposed remediation:", ""]
        for key in (
            "problem",
            "boundary",
            "control",
            "location",
            "test",
            "remediation_evidence",
            "status",
        ):
            lines += [f"- **{key.replace('_', ' ').capitalize()}:** {escape(r[key])}"]
        lines += ["", *["- " + escape(v) for v in f["limitations"]], ""]
    lines += [
        "## Indeterminate observations",
        "",
        "No confirmed-vulnerability severity is assigned. These outcomes remain unresolved.",
        "",
    ]
    for o in report["unresolved_observations"]:
        lines += [
            f"### {escape(o['attack_id'])}",
            "",
            escape(" ".join(o["reasons"])),
            "",
            "Available: " + escape(", ".join(o["available_evidence"])),
            "",
            "Missing or unresolved: " + escape("; ".join(o["missing_evidence"])),
            "",
            "Next verification: " + escape(o["next_verification"]),
            "",
        ]
    lines += [
        "## Blocked/not-observed scenarios",
        "",
        f"{len(report['blocked_attacks'])} executions retain BLOCKED_OR_NOT_OBSERVED. "
        "No vulnerability or universal defense is inferred. Exact reasons appear in the appendix.",
        "",
        "## Execution issues",
        "",
    ]
    lines += [
        escape(o["attack_id"] + ": " + " ".join(o["reasons"])) for o in report["execution_issues"]
    ] or ["No recorded failed, timed-out or skipped executions."]
    lines += [
        "",
        f"Unrecorded definitions: {s['unrecorded_definitions']}; their outcomes are unknown.",
        "",
        "## Prioritized remediation plan and verification strategy",
        "",
        "Proposed work only. Address findings in severity order; share a trusted task-policy "
        "enforcement layer where implementation review supports it. Use each finding's exact "
        "operation/resource checks and benign controls. Save a new scan and compare correlated "
        "denials plus unchanged state to this baseline. Resolve semantic indeterminate cases "
        "with independently reviewed expectations. No remediation is implemented here.",
        "",
    ]
    for index, f in enumerate(report["findings"], 1):
        lines += [f"{index}. {escape(f['title'])}: {escape(f['recommendation']['control'])}"]
    lines += [
        "",
        "## Limitations and provenance",
        "",
        *["- " + escape(v) for v in report["limitations"]],
        "",
        "Source directory: " + escape(p["source_directory"]),
        "",
        "Report schema: "
        + escape(report["schema_version"])
        + "; source schema: "
        + escape(p["source_schema_version"]),
        "",
        escape(p["consistency"]),
        "",
        "| Source artifact | SHA-256 |",
        "| --- | --- |",
    ]
    for name, value in sorted(report["artifact_digests"].items()):
        lines.append(f"| {escape(name)} | {value} |")
    lines += [
        "",
        "Current fixture/code matches source: " + str(p["current_fixture_matches"]),
        "",
        "Implementation evidence (current files, hashes recorded in JSON):",
        "",
    ]
    lines += [
        "- " + escape(path) + ": " + value
        for path, value in sorted(p["implementation_evidence"].items())
    ]
    lines += [
        "",
        "## Complete attack outcome appendix",
        "",
        "| Attack | Revision | Category | Execution | Detector verdict | Finding | Reason |",
        "| --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for o in report["attack_outcomes"]:
        lines.append(
            "| "
            + " | ".join(
                escape(v)
                for v in (
                    o["attack_id"],
                    o["revision"],
                    o["category"],
                    o["status"],
                    o["verdict"] or "Not evaluated",
                    o["finding_id"] or "None",
                    "; ".join(o["reasons"]),
                )
            )
            + " |"
        )
    return "\n".join(lines) + "\n"
