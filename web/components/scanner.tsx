import type { Counts } from "../lib/snapshot";

export function Outcomes({ counts }: { counts: Counts | null }) {
  if (counts && !counts.recorded_executions)
    return <output>This snapshot contains no recorded executions.</output>;
  const rows = [
    ["Blocked or not observed", counts?.blocked_or_not_observed, "blocked"],
    [
      "Observed attack success",
      counts?.successful_attack_executions,
      "observed",
    ],
    ["Indeterminate", counts?.indeterminate, "unresolved"],
  ] as const;
  let ring;
  if (counts) {
    const blocked = (100 * counts.blocked_or_not_observed) / counts.recorded_executions;
    const observed = blocked + (100 * counts.successful_attack_executions) / counts.recorded_executions;
    ring = `conic-gradient(var(--series) 0 ${blocked}%, var(--observed) ${blocked}% ${observed}%, var(--unresolved) ${observed}% 100%)`;
  }
  return (
    <div className="outcomes" aria-hidden={counts === null ? true : undefined}>
      <div className="outcome-total" style={{ backgroundImage: ring }}>
        <strong>{counts?.recorded_executions}</strong>
        <span>recorded executions</span>
      </div>
      <dl className="legend">
        {rows.map(([label, count, color]) => (
          <div key={label}>
            <dt>
              <i className={color} />
              {label}
            </dt>
            <dd>{count ?? "0"}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
