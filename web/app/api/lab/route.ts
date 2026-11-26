import { boundedBody } from "../../../lib/bounded-body";
import { NextRequest, NextResponse } from "next/server";
import { randomUUID } from "node:crypto";
import { cases, type CaseId, type Run } from "../../../lib/lab-cases";
import { labEnabled, runCase } from "../../../lib/lab-runner";
import {
  labState as state,
  labCookie as cookie,
} from "../../../lib/lab-session";
const answer = (status: number, data: object) =>
  NextResponse.json(data, {
    status,
    headers: { "Cache-Control": "private, no-store" },
  });
function gate(req: NextRequest, write = false) {
  if (!labEnabled())
    return answer(503, {
      message: "Execution requires the local isolated runner.",
    });
  const origin = process.env.FRONTEND_ORIGIN!;
  if (
    req.headers.get("host") !== new URL(origin).host ||
    (write && req.headers.get("origin") !== origin)
  )
    return answer(403, { message: "Request origin rejected." });
  return null;
}
function lookup(req: NextRequest) {
  const now = Date.now();
  for (const [id, visitor] of state.visitors)
    if (!visitor.busy && visitor.until < now) state.visitors.delete(id);
  const id = req.cookies.get(cookie)?.value ?? "";
  return { id, visitor: state.visitors.get(id) };
}
export function GET(req: NextRequest) {
  const denied = gate(req);
  if (denied) return denied;
  return answer(200, { runs: lookup(req).visitor?.runs ?? [] });
}
export async function POST(req: NextRequest) {
  const denied = gate(req, true);
  if (denied) return denied;
  if (req.headers.get("content-type") !== "text/plain;charset=UTF-8")
    return answer(415, { message: "Unexpected request type." });
  let name: string;
  try {
    name = await boundedBody(req, 24);
  } catch {
    return answer(413, { message: "Request too large or incomplete." });
  }
  let { id, visitor } = lookup(req);
  if (name === "reset") {
    if (visitor?.busy)
      return answer(409, { message: "Wait for the current run." });
    if (visitor) visitor.runs = [];
    return answer(200, { runs: [] });
  }
  if (!Object.hasOwn(cases, name))
    return answer(400, { message: "Choose a listed case." });
  const now = Date.now();
  state.starts = state.starts.filter((t) => t > now - 60000);
  if (
    state.active >= 2 ||
    state.starts.length >= 18 ||
    visitor?.busy ||
    (visitor?.starts.filter((t) => t > now - 60000).length ?? 0) >= 5 ||
    (!visitor && state.visitors.size >= 128)
  )
    return answer(429, {
      message:
        "The runner is busy or its minute limit was reached. Try again shortly.",
    });
  if (!visitor) {
    id = randomUUID();
    visitor = { until: now + 1800000, starts: [], busy: false, runs: [] };
    state.visitors.set(id, visitor);
  }
  visitor.until = now + 1800000;
  visitor.starts = visitor.starts.filter((t) => t > now - 60000);
  visitor.starts.push(now);
  state.starts.push(now);
  visitor.busy = true;
  state.active++;
  try {
    const result = await runCase(name as CaseId);
    const run: Run = {
      ...result,
      id: randomUUID(),
      at: new Date(now).toISOString(),
      elapsed: Date.now() - now,
      scenario: name as CaseId,
    };
    visitor.runs = [run, ...visitor.runs].slice(0, 12);
    if (state.visitors.get(id) !== visitor)
      return answer(409, { message: "This visitor session ended." });
    const res = answer(200, { run });
    res.cookies.set(cookie, id, {
      httpOnly: true,
      sameSite: "strict",
      path: "/",
      maxAge: 1800,
    });
    return res;
  } catch {
    return answer(503, {
      message:
        "The runner could not complete this case. Check the local runtime and try again.",
    });
  } finally {
    visitor.busy = false;
    state.active--;
  }
}
