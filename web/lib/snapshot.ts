// Only these six aggregate fields may enter the public snapshot.
export const countNames = [
  "recorded_executions",
  "blocked_or_not_observed",
  "successful_attack_executions",
  "indeterminate",
  "distinct_findings",
  "observed_effects",
] as const;
export type Counts = Record<(typeof countNames)[number], number>;

export function readCounts(input: unknown): Counts {
  if (!input || typeof input !== "object") throw new Error("Invalid snapshot");
  const counts = {} as Counts;
  for (const key of countNames) {
    const value: unknown = Reflect.get(input, key);
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
      throw new Error("Invalid count");
    counts[key] = value;
  }
  if (
    counts.recorded_executions !==
    counts.blocked_or_not_observed +
      counts.successful_attack_executions +
      counts.indeterminate
  )
    throw new Error("Inconsistent totals");
  return counts;
}
