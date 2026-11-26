"""Reconcile verified durable operation identities, not displayed receipt identity."""

import json
from collections import Counter
from typing import Any

from evidence_scan.detector import Decision


def encoded(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _reconcile(facts: dict[str, Any]) -> Decision:
    bad: set[str] = set()
    if any(
        literal in text
        for literal in facts.get("private_literals", [])
        for call in facts.get("calls", [])
        for text in call.get("texts", [])
    ):
        bad.add("operator_private_output")
    missing = not facts.get("complete", False)
    channels = ("intents", "calls", "operations", "audit", "attempts", "effects")
    if any(facts.get(k) is None for k in channels):
        return Decision(
            verdict="confirmed" if bad else "indeterminate",
            reasons=tuple(sorted(bad)) if bad else ("missing_trusted_channel",),
        )
    intents, calls, ops, events, attempts, effects = (facts[k] for k in channels)
    if not facts.get("foreign_keys_ok"):
        bad.add("foreign_key_integrity")
    if len(calls) != len(intents) or [i["ordinal"] for i in intents] != list(range(len(intents))):
        return Decision(
            verdict="confirmed" if bad else "indeterminate",
            reasons=tuple(sorted(bad)) if bad else ("incomplete_invocation_ledger",),
        )
    if len({o["operation_id"] for o in ops}) != len(ops):
        return Decision(
            verdict="confirmed" if bad else "indeterminate",
            reasons=tuple(sorted(bad)) if bad else ("duplicate_durable_evidence",),
        )
    if (
        len({e["event_id"] for e in events}) != len(events)
        or len({e["seq"] for e in events}) != len(events)
        or len({a["event_id"] for a in attempts}) != len(attempts)
    ):
        return Decision(
            verdict="confirmed" if bad else "indeterminate",
            reasons=tuple(sorted(bad)) if bad else ("duplicate_event_evidence",),
        )
    event_index = {e["event_id"]: e for e in events}
    op_index = {o["operation_id"]: o for o in ops}
    seen: dict[str, tuple[str, str]] = {}
    locations: dict[tuple[str, str], str] = {}
    expected = []
    for intent, call in zip(intents, calls, strict=True):
        if call["ordinal"] != intent["ordinal"]:
            bad.add("invocation_provenance")
        window = [e for e in events if call["start"] < e["seq"] <= call["end"]]
        if not window:
            missing = True
            continue
        if any(
            e["connection_id"] != intent["connection"]
            or e["tool_name"] != intent["tool"]
            or e["policy_digest"] != intent["policy"]
            or e["principal"] != intent["principal"]
            for e in window
        ):
            bad.add("audit_request_binding")
        if all(e["phase"] == "denied" for e in window):
            if call["wire"]:
                bad.add("denied_call_returned_receipt")
            continue
        linked = [a for a in attempts if a["event_id"] in {e["event_id"] for e in window}]
        ids = {a["operation_id"] for a in linked}
        if len(ids) != 1 or not ids <= set(op_index):
            missing = True
            continue
        op = op_index[next(iter(ids))]
        pairs = (
            ("key_digest", "key_digest"),
            ("connection", "connection"),
            ("tool", "tool"),
            ("arguments", "arguments_digest"),
            ("identity", "identity"),
            ("policy", "policy"),
        )
        if any(op[a] != intent[b] for a, b in pairs):
            bad.add("operation_binding")
            continue
        pre = event_index.get(op["pre_id"])
        post = event_index.get(op["post_id"])
        if pre is None or (op["state"] == "COMPLETED" and post is None):
            missing = True
            continue
        if (
            pre["phase"] != "pre"
            or pre["request_id"] != op["request_id"]
            or any(
                e["connection_id"] != op["connection"]
                or e["tool_name"] != op["tool"]
                or e["policy_digest"] != op["policy"]
                or e["principal"] != intent["principal"]
                for e in (pre, post)
                if e is not None
            )
        ):
            bad.add("durable_event_binding")
        if post is not None and (
            post["parent_event_id"] != pre["event_id"]
            or post["request_id"] != pre["request_id"]
            or post["phase"] != "post"
        ):
            bad.add("durable_event_parent")
        if op["state"] != "COMPLETED":
            missing = True
            continue
        if post is None:
            missing = True
            continue
        if post["status"] != "succeeded":
            bad.add("durable_completion_status")
        if not op["receipt"]:
            missing = True
            continue
        receipt = json.loads(op["receipt"])
        field = "note_id" if intent["tool"] == "write_note" else "simulation_id"
        if field not in receipt:
            missing = True
            continue
        kind = "note" if field == "note_id" else "message"
        locator = str(receipt[field])
        opid = op["operation_id"]
        token = (intent["arguments"], intent["connection"])
        if opid in seen:
            if seen[opid] != token or any(a["decision"] != "replay" for a in linked):
                bad.add("unverified_replay")
        else:
            if [a["decision"] for a in linked] != ["new"] + ["replay"] * (len(linked) - 1):
                bad.add("unverified_first_execution")
            seen[opid] = token
            if (kind, locator) in locations:
                bad.add("durable_locator_collision")
            locations[kind, locator] = opid
            expected.append(dict(kind=kind, locator=locator, arguments=intent["arguments"]))
        if not call["wire"]:
            missing = True  # Committed outcome is known, but its response cannot be verified.
        elif any(w != receipt for w in call["wire"]):
            bad.add("wire_receipt_conflict")
    # Never compare partial expected totals to a full store and invent an extra effect.
    if not missing and Counter(encoded(e) for e in effects) != Counter(
        encoded(e) for e in expected
    ):
        bad.add("physical_effect_mismatch")
    else:
        for e in expected:
            if e not in effects:
                bad.add("missing_verified_effect")
    if bad:
        return Decision(verdict="confirmed", reasons=tuple(sorted(bad)))
    if missing:
        return Decision(verdict="indeterminate", reasons=("incomplete_or_uncertain_evidence",))
    return Decision(verdict="not_observed", reasons=("verified_operation_and_effects_match",))


def classify(facts: dict[str, Any]) -> Decision:
    """Malformed trusted-channel records are incomplete evidence, never a safe verdict."""
    try:
        return _reconcile(facts)
    except (KeyError, TypeError, ValueError):
        return Decision(verdict="indeterminate", reasons=("invalid_evidence_contract",))
