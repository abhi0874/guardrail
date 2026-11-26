"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import {
  ArrowRight,
  Clock3,
  History,
  Play,
  RotateCcw,
  ScanLine,
  SquareTerminal,
} from "lucide-react";
import { cases, type Run, type CaseId } from "../lib/lab-cases";
import recordings from "../lib/recorded-lab.json";

type ReceiptData = Pick<Run, "verdict" | "summary" | "trace" | "elapsed">;
function Receipt({ run }: { run: ReceiptData }) {
  return (
    <div className="receipt">
      <div className="receipt-top">
        <strong>{run.verdict.replaceAll("_", " ").toLowerCase()}</strong>
        <span>
          <Clock3 size={13} /> {run.elapsed} ms
        </span>
      </div>
      <p>{run.summary}</p>
      <h3>Execution trace</h3>
      <ol>
        {run.trace.map((v, i) => (
          <li key={i}>
            <span>{String(i + 1).padStart(2, "0")}</span>
            {v.replaceAll("_", " ")}
          </li>
        ))}
      </ol>
    </div>
  );
}
export function Lab({
  scanner,
  enabled,
}: {
  scanner: boolean;
  enabled: boolean;
}) {
  const choices: CaseId[] = scanner
    ? ["reader", "visibility"]
    : ["health", "document"];
  const [scenario, setScenario] = useState<CaseId>(choices[0]),
    [run, setRun] = useState<ReceiptData | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  async function execute() {
    setError("");
    setRun(null);
    setBusy(true);
    try {
      const r = await fetch("/api/lab/", { method: "POST", body: scenario });
      const data = await r.json();
      if (!r.ok) throw Error(data.message);
      setRun(data.run);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Run unavailable.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="page-head">
        <h1>{scanner ? "Security Scanner" : "Agent Playground"}</h1>
        <p>
          {!enabled
            ? "Choose a recorded example to explore its result and execution trace."
            : scanner
            ? "Exercise document-access boundaries with a disposable reader identity."
            : "Call a read-only MCP tool against an isolated synthetic workspace."}
        </p>
      </div>
      <div className="lab-grid">
        <section className="panel content-card">
          <div className="section-title">
            {scanner ? <ScanLine /> : <SquareTerminal />}
            <h2>
              {scanner ? "Choose a security check" : "Choose an operation"}
            </h2>
          </div>
          <fieldset className="case-picker" disabled={busy}>
            <legend className="sr-only">Available cases</legend>
            {choices.map((id) => (
              <label key={id} aria-label={cases[id].label}>
                <input
                  type="radio"
                  name="scenario"
                  checked={scenario === id}
                  onChange={() => {
                    setScenario(id);
                    setRun(null);
                    setError("");
                  }}
                />
                <span>
                  <strong>{cases[id].label}</strong>
                  <small>{cases[id].description}</small>
                </span>
              </label>
            ))}
          </fieldset>
          <button
            className="primary"
            disabled={busy}
            onClick={() => enabled ? void execute() : setRun(recordings[scenario])}
          >
            <Play size={15} />
            {!enabled ? "View recorded trace" : busy ? "Running…" : scanner ? "Run check" : "Run operation"}
          </button>
        </section>
        <section
          className="panel content-card"
          aria-live="polite"
          aria-busy={busy}
        >
          <div className="section-title">
            <h2>{enabled ? "Execution result" : "Recorded result"}</h2>
          </div>
          {run ? (
            <Receipt run={run} />
          ) : (
            <div className={busy ? "empty-state skeleton" : "empty-state"}>
              <SquareTerminal />
              <p>
                {busy
                  ? "Waiting for the isolated runner…"
                  : error || (enabled ? "Run a case to see the observed result and trace." : "Select an example and open its recorded trace.")}
              </p>
            </div>
          )}
          {enabled && run && (
            <Link href="/history/" className="text-link">
              View execution history <ArrowRight size={14} />
            </Link>
          )}
        </section>
      </div>
      <Link
        className="catalog-link panel"
        href={scanner ? "/tests/" : "/tools/"}
      >
        {scanner ? <History /> : <SquareTerminal />}
        <span>
          <b>{scanner ? "Recorded security tests" : "MCP tool contracts"}</b>
          <small>
            {scanner
              ? "Explore the saved Scanner evidence."
              : "Inspect schemas and access requirements."}
          </small>
        </span>
        <ArrowRight />
      </Link>
    </>
  );
}
export function RunHistory({ enabled }: { enabled: boolean }) {
  const [runs, setRuns] = useState<Run[]>([]),
    [message, setMessage] = useState(""),
    [busy, setBusy] = useState(enabled);
  async function refresh(reset = false) {
    setBusy(true);
    setMessage("");
    try {
      const r = await fetch(
        "/api/lab/",
        reset ? { method: "POST", body: "reset" } : { cache: "no-store" },
      );
      const data = await r.json();
      if (!r.ok) throw Error(data.message);
      setRuns(data.runs);
    } catch {
      setMessage("Could not load this browser’s execution history.");
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    if (enabled) {
      const timer = setTimeout(() => void refresh(), 0);
      return () => clearTimeout(timer);
    }
  }, [enabled]);
  return (
    <>
      <div className="page-head">
        <h1>Execution History</h1>
        <p>
          Up to twelve recent local runs from this browser. Results expire after
          30 minutes of inactivity.
        </p>
      </div>
      <section className="panel content-card history-card">
        <div className="section-title">
          <History />
          <h2>Recent runs</h2>
        </div>
        <output className={runs.length ? "muted" : "history-empty"}>
          {busy
            ? "Loading runs…"
            : message ||
              (!enabled
                ? "The local runner is offline."
                : !runs.length
                  ? "No runs in this browser yet."
                  : "")}
        </output>
        {runs.map((run) => (
          <details key={run.id}>
            <summary>
              {cases[run.scenario].label} ·{" "}
              {new Date(run.at).toLocaleTimeString()}
            </summary>
            <Receipt run={run} />
          </details>
        ))}
        <div className="actions">
          <Link className="text-link" href="/playground/">
            Open playground <ArrowRight size={15} />
          </Link>
          {enabled && (
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void refresh(false)}
            >
              Refresh
            </button>
          )}
          {runs.length > 0 && (
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void refresh(true)}
            >
              <RotateCcw size={14} /> Clear history
            </button>
          )}
        </div>
      </section>
    </>
  );
}
