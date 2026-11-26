import Link from "next/link";
import {
  ArrowRight,
  ArrowUpRight,
  Blocks,
  ChartNoAxesColumnIncreasing,
  Check,
  Fingerprint,
  FlaskConical,
  GitBranch,
  ScanLine,
  ShieldCheck,
  SquareTerminal,
} from "lucide-react";
import { release, tools } from "../lib/catalog";
import { scannerSnapshot } from "../lib/export";
import { Outcomes } from "../components/scanner";

export default function Overview() {
  const counts = scannerSnapshot();
  return (
    <>
      <div className="page-head title-row">
        <div>
          <h1>Security overview</h1>
          <p>
            Explore the MCP agent, its guardrails, and the evidence behind them.
          </p>
        </div>
        <span className="release-ref">
          <GitBranch size={14} /> {release.sha}
        </span>
      </div>
      <div className="overview-lead">
        <section className="lab-hero" aria-labelledby="hero-title">
          <div>
            <span className="hero-label">
              <SquareTerminal size={16} /> Agent playground
            </span>
            <h2 id="hero-title">Inside the guardrails.</h2>
            <p>
              Follow an MCP request from its first security check to the tool’s
              response.
            </p>
            <Link className="hero-button" href="/playground/">
              Open playground <ArrowRight size={16} />
            </Link>
          </div>
          <div className="print-art" aria-hidden="true">
            <Fingerprint />
          </div>
        </section>
        <section className="panel content-card outcome-card">
          <div className="section-title">
            <h2>Scanner outcomes</h2>
            <Link
              href="/tests/"
              className="icon-link"
              aria-label="View security tests"
            >
              <ArrowUpRight />
            </Link>
          </div>
          <p className="muted">Recorded synthetic executions</p>
          <Outcomes counts={counts} />
        </section>
      </div>
      <div className="section-caption">
        <h2>Release snapshot</h2>
        <span>Historical CI results</span>
      </div>
      <div className="metric-grid">
        {(
          [
            [FlaskConical, "MCP tests", release.mcp, "Passed in release CI"],
            [
              ScanLine,
              "Scanner regressions",
              release.scanner,
              "Passed in release CI",
            ],
            [
              ChartNoAxesColumnIncreasing,
              "Source coverage",
              release.coverage,
              "Measured in release CI",
            ],
          ] as const
        ).map(([Icon, label, value, detail]) => {
          return (
            <article className="metric panel" key={label}>
              <div className="metric-title">
                <span>{label}</span>
                <Icon />
              </div>
              <strong>{value}</strong>
              <small>{detail}</small>
            </article>
          );
        })}
      </div>
      <div className="two-col">
        <section className="panel content-card">
          <div className="section-title">
            <ShieldCheck size={20} />
            <h2>Isolation evidence</h2>
          </div>
          <p className="muted">Recorded cross-client acceptance check</p>
          <ul className="checks">
            {[
              ["Request denied", "HTTP 409 with an explicit denial"],
              [
                "No unauthorized effects",
                "Notes, operations and approvals preserved",
              ],
              ["Durable evidence", "One denied attempt recorded"],
            ].map(([name, detail]) => (
              <li key={name}>
                <Check />
                <div>
                  <strong>{name}</strong>
                  <small>{detail}</small>
                </div>
              </li>
            ))}
          </ul>
          <Link className="text-link" href="/audit/">
            View audit evidence <ArrowRight size={14} />
          </Link>
        </section>
        <Link className="catalog-link catalog-feature panel" href="/tools/">
          <Blocks />
          <span>
            <b>MCP tool catalog</b>
            <small>Six registered contracts and their access boundaries</small>
            <span className="contract-counts">
              {(
                ["Protected read", "Protected write", "Internal only"] as const
              ).map((mode) => (
                <span key={mode}>
                  {tools.filter(([, , access]) => access === mode).length} ·{" "}
                  {mode}
                </span>
              ))}
            </span>
          </span>
          <ArrowRight />
        </Link>
      </div>
    </>
  );
}
