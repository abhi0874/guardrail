"use client";
import { useState } from "react";
export function LiveStatus() {
  const [state, setState] = useState("Not checked");
  const [busy, setBusy] = useState(false);
  async function check() {
    setBusy(true);
    setState("Checking the local readiness endpoint…");
    try {
      const res = await fetch("/api/status/", {
        credentials: "omit",
        redirect: "error",
        signal: AbortSignal.timeout(12000),
      });
      const value = await res.json();
      setState(
        res.ok && value.status === "ready"
          ? "Backend ready · checked " + value.checkedAt
          : value.reason === "timeout"
            ? "Readiness check timed out."
            : value.reason === "network"
              ? "Readiness network connection failed. Check again later."
              : "Backend readiness is unavailable.",
      );
    } catch {
      setState("Readiness check unavailable. Check again later.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section>
      <h2>Backend readiness</h2>
      <p>
        This edition has no live backend connection. The check reports the
        local readiness endpoint status.
      </p>
      <output>{state}</output>
      <br />
      <button disabled={busy} className="secondary" onClick={check}>
        Check backend readiness
      </button>
    </section>
  );
}
