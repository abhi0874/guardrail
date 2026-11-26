"use client";
import { useEffect, useState } from "react";
import {
  BarChart,
  CartesianGrid,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
const samples = [
  {
    name: "Readiness",
    p50: 69.61,
    p95: 89.94,
    p99: 89.94,
    n: 6,
    context: "Warm, concurrency 1",
  },
  {
    name: "Readiness c2",
    p50: 80.11,
    p95: 119.4,
    p99: 119.4,
    n: 6,
    context: "Warm, concurrency 2",
  },
  {
    name: "MCP health",
    p50: 1530.17,
    p95: 1849.22,
    p99: 1849.22,
    n: 6,
    context: "Warm, concurrency 1",
  },
  {
    name: "MCP health c2",
    p50: 1719.61,
    p95: 2169.18,
    p99: 2169.18,
    n: 6,
    context: "Warm, concurrency 2",
  },
  {
    name: "Note write",
    p50: 2817.71,
    p95: 2871.09,
    p99: 2871.09,
    n: 3,
    context: "Warm, serial",
  },
];
export function Performance() {
  const [metric, setMetric] = useState("p95");
  const [animate, setAnimate] = useState(false);
  useEffect(() => {
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setAnimate(!query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return (
    <>
      <div className="chart-head">
        <h2>Historical hosted latency</h2>
        <label>
          Percentile
          <select
            aria-label="Percentile"
            value={metric}
            onChange={(e) => setMetric(e.target.value)}
          >
            {["p50", "p95", "p99"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </label>
      </div>
      <section
        className="chart"
        aria-label={
          "Historical hosted " +
          metric +
          " latency in milliseconds; exact values in the table below"
        }
      >
        <ResponsiveContainer width="100%" height={280}>
          <BarChart
            data={samples}
            margin={{ top: 12, right: 8, bottom: 4, left: -6 }}
          >
            <CartesianGrid
              vertical={false}
              stroke="var(--line)"
              strokeDasharray="3 5"
            />
            <XAxis
              axisLine={false}
              tickLine={false}
              dataKey="name"
              tick={{ fill: "var(--muted)", fontSize: 11 }}
            />
            <YAxis
              axisLine={false}
              tickLine={false}
              tick={{ fill: "var(--muted)" }}
            />
            <Tooltip
              contentStyle={{
                background: "var(--panel)",
                color: "var(--text)",
              }}
            />
            <Bar
              dataKey={metric}
              radius={[6, 6, 0, 0]}
              maxBarSize={56}
              fill="var(--series)"
              isAnimationActive={animate}
              animationDuration={190}
              animationEasing="ease-out"
            />
          </BarChart>
        </ResponsiveContainer>
      </section>
      <div className="table-scroll">
        <table>
          <caption>
            Phase 2H, revision 0476fae. India client → Render Singapore /
            Supabase Mumbai.
          </caption>
          <thead>
            <tr>
              <th>Workload</th>
              <th>p50 ms</th>
              <th>p95 ms</th>
              <th>p99 ms</th>
              <th>Samples</th>
            </tr>
          </thead>
          <tbody>
            {samples.map((s) => (
              <tr key={s.name}>
                <th>
                  {s.name}
                  <small>{s.context}</small>
                </th>
                <td>{s.p50}</td>
                <td>{s.p95}</td>
                <td>{s.p99}</td>
                <td>{s.n}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p>
        Small samples limit tail estimates. These are client-observed totals;
        internal attribution is unmeasured. After 20 minutes idle, one request
        took 22.496 seconds. Provider spin-down was unconfirmed. Local
        performance targets and synthetic detector accuracy are separate
        measurements.
      </p>
    </>
  );
}
