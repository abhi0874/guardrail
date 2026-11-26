"use client";
import { useSyncExternalStore } from "react";
import Link from "next/link";
import type { Evidence, Finding } from "../lib/evidence";

function subscribe(callback: () => void) {
  window.addEventListener("filters", callback);
  window.addEventListener("popstate", callback);
  return () => {
    window.removeEventListener("filters", callback);
    window.removeEventListener("popstate", callback);
  };
}
export const verdictLabel: Record<string, string> = {
  SUCCESS: "Observed success",
  BLOCKED_OR_NOT_OBSERVED: "Blocked or not observed",
  INDETERMINATE: "Indeterminate",
};
export function Explorer({
  data,
  mode = "findings",
}: {
  data: Evidence;
  mode?: "findings" | "attacks" | "audit";
}) {
  const search = useSyncExternalStore(
    subscribe,
    () => location.search,
    () => "",
  );
  const params = new URLSearchParams(search);
  const query = params.get("q") ?? "",
    severity = params.get("severity") ?? "",
    category = params.get("category") ?? "",
    outcome = params.get("outcome") ?? "",
    sort = params.get("sort") ?? "title";
  function update(key: string, value: string) {
    const next = new URLSearchParams(location.search);
    next.set(key, value);
    history.replaceState(null, "", "?" + next);
    window.dispatchEvent(new Event("filters"));
  }
  const categories = [...new Set(data.attacks.map((a) => a.category))].sort();
  const rows =
    mode === "findings"
      ? data.findings.map((f) => ({
          id: f.finding_id,
          title: f.title,
          category: f.categories,
          band: f.severity.band,
          score: f.severity.score,
          statuses: data.attacks
            .filter((a) => f.associated_attack_ids.includes(a.attack_id))
            .map((a) => a.detector_verdict),
        }))
      : data.attacks.map((a) => ({
          id: a.attack_id,
          title: a.title,
          category: [a.category],
          band: "",
          score: 0,
          statuses: [a.detector_verdict],
        }));
  const filtered = rows
    .filter(
      (r) =>
        (r.title + " " + r.id).toLowerCase().includes(query.toLowerCase()) &&
        (!severity || r.band === severity) &&
        (!category || r.category.includes(category)) &&
        (!outcome || r.statuses.some((s) => s === outcome)),
    )
    .sort((a, b) =>
      sort === "severity"
        ? b.score - a.score || a.id.localeCompare(b.id)
        : (sort === "id" ? a.id : a.title).localeCompare(
            sort === "id" ? b.id : b.title,
          ),
    );
  return (
    <>
      <p className="muted">
        Recorded synthetic sandbox · 3 November 2026. Custom severity describes
        this fixture.
      </p>
      <div className="filters">
        <label>
          Search
          <input
            aria-label="Search"
            maxLength={160}
            value={query}
            onChange={(e) => update("q", e.target.value)}
            placeholder="Title or identifier"
          />
        </label>
        {mode === "findings" && (
          <label>
            Severity
            <select
              aria-label="Severity"
              value={severity}
              onChange={(e) => update("severity", e.target.value)}
            >
              <option value="">All severities</option>
              {["Critical", "High", "Medium", "Low", "Informational"].map(
                (v) => (
                  <option key={v}>{v}</option>
                ),
              )}
            </select>
          </label>
        )}
        <label>
          Category
          <select
            aria-label="Category"
            value={category}
            onChange={(e) => update("category", e.target.value)}
          >
            <option value="">All categories</option>
            {categories.map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </label>
        <label>
          Outcome
          <select
            aria-label="Outcome"
            value={outcome}
            onChange={(e) => update("outcome", e.target.value)}
          >
            <option value="">All outcomes</option>
            {Object.entries(verdictLabel).map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Sort
          <select
            aria-label="Sort"
            value={sort}
            onChange={(e) => update("sort", e.target.value)}
          >
            <option value="title">Title</option>
            <option value="id">Identifier</option>
            {mode === "findings" && (
              <option value="severity">Severity score</option>
            )}
          </select>
        </label>
        <button
          className="secondary"
          onClick={() => {
            history.replaceState(null, "", location.pathname);
            window.dispatchEvent(new Event("filters"));
          }}
        >
          Reset filters
        </button>
      </div>
      <p aria-live="polite">
        {filtered.length} of {rows.length}{" "}
        {mode === "findings" ? "findings" : "scenario records"}
      </p>
      {!filtered.length && <p>No results match these filters.</p>}
      <ul className="result-list">
        {filtered.map((r) => (
          <li key={r.id}>
            <Link
              href={
                (mode === "findings" ? "/findings/" : "/attacks/") +
                r.id +
                "/?" +
                params
              }
            >
              <strong>{r.title}</strong>
              <small>{r.id}</small>
              <span>
                {r.band
                  ? r.band + " · " + r.score + " / 10"
                  : verdictLabel[r.statuses[0]]}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </>
  );
}
export function FindingDetail({
  finding,
  data,
}: {
  finding: Finding;
  data: Evidence;
}) {
  return (
    <>
      <h1>{finding.title}</h1>
      <p>
        {finding.finding_id} · {finding.severity.band} ·{" "}
        {finding.severity.score} / 10 (custom rubric)
      </p>
      <p>Evidence confidence: {finding.confidence}</p>
      <p>{finding.mechanism}</p>
      <h2>Related attack evidence</h2>
      {finding.observations.map((o, i) => (
        <article key={i} className="detail">
          <Link href={"/attacks/" + o.attack_id + "/"}>
            {data.attacks.find((a) => a.attack_id === o.attack_id)?.title}
          </Link>
          <p>{o.effect}</p>
          {o.evidence.map((e, j) => (
            <p key={j}>
              <code>{e.pointer}</code> — {e.purpose}
            </p>
          ))}
        </article>
      ))}
      <h2>Limitations</h2>
      <ul>
        {finding.limitations.map((v) => (
          <li key={v}>{v}</li>
        ))}
      </ul>
    </>
  );
}
