import "server-only";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { resolve, join } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";
import type { CaseId } from "./lab-cases";
const execute = promisify(execFile);
const resultSchema = z.strictObject({
  verdict: z.enum([
    "COMPLETED",
    "SUCCESS",
    "BLOCKED_OR_NOT_OBSERVED",
    "INDETERMINATE",
  ]),
  summary: z.string().min(1).max(512),
  trace: z.array(z.string().max(40)).min(1).max(16),
});
export function labEnabled() {
  return (
    process.env.RECRUITER_LOCAL_LAB === "1" &&
    !process.env.VERCEL &&
    /^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(process.env.FRONTEND_ORIGIN ?? "")
  );
}
export async function runCase(scenario: CaseId) {
  if (!labEnabled()) throw Error("Local runtime disabled");
  const root = resolve(/* turbopackIgnore: true */ process.cwd(), "..");
  const audit = join(root, ".runtime", "audit");
  await mkdir(audit, { recursive: true, mode: 0o700 });
  const work = await mkdtemp(join(audit, "recruiter-"));
  try {
    const { stdout } = await execute(
      join(root, ".venv/bin/python"),
      ["-I", "-B", join(root, "web/sandbox/worker.py"), scenario],
      {
        cwd: work,
        encoding: "utf8",
        env: { NODE_ENV: "test", PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
        maxBuffer: 8192,
        timeout: 8000,
        killSignal: "SIGKILL",
      },
    );
    return resultSchema.parse(JSON.parse(stdout));
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
