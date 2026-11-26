"use client";
import { useState, useEffect } from "react";
import { readCounts, type Counts } from "../lib/snapshot";
import { Outcomes } from "./scanner";

type State = { kind: "loading" | "error" } | { kind: "ready"; counts: Counts };
export function SnapshotReader() {
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<State>({ kind: "loading" });
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timer = setTimeout(() => controller.abort(), 8000);
    async function load() {
      try {
        const res = await fetch("/data/scanner.json", {
          signal: controller.signal,
          credentials: "omit",
          redirect: "error",
        });
        if (!res.ok) throw new Error();
        const counts = readCounts(await res.json());
        if (active) setState({ kind: "ready", counts });
      } catch {
        if (active) setState({ kind: "error" });
      } finally {
        clearTimeout(timer);
      }
    }
    void load();
    return () => {
      active = false;
      clearTimeout(timer);
      controller.abort();
    };
  }, [attempt]);
  const counts = state.kind === "ready" ? state.counts : null;
  const hasExecutions = Boolean(counts?.recorded_executions);
  return (
    <div className="snapshot-summary">
      <Outcomes counts={hasExecutions ? counts : null} />
      {!hasExecutions && (
        <div className="snapshot-status">
          {state.kind === "error" ? (
            <div role="alert">
              <p>The saved snapshot could not be read.</p>
              <button
                className="secondary"
                onClick={() => {
                  setState({ kind: "loading" });
                  setAttempt(attempt + 1);
                }}
              >
                Reload snapshot
              </button>
            </div>
          ) : (
            <output>
              {state.kind === "loading"
                ? "Loading saved snapshot…"
                : "This snapshot contains no recorded executions."}
            </output>
          )}
        </div>
      )}
    </div>
  );
}
