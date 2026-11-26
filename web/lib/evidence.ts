import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { z } from "zod";

const id = z.string().regex(/^[a-z0-9-]{1,100}$/);
const verdict = z.enum(["SUCCESS", "BLOCKED_OR_NOT_OBSERVED", "INDETERMINATE"]);
const text = z.string().max(30000);
const event = z.object({
  sequence: z.number().int().nonnegative(),
  event_type: text,
});
const attack = z.object({
  schema_version: z.literal("api-1.0"),
  attack_id: id,
  title: text,
  category: text,
  status: text,
  detector_verdict: verdict,
  definition: z.object({ description: text, expected_security_boundary: text }),
  request: z.object({ user_message: text }),
  detector: z.object({ findings: z.array(z.object({ explanation: text })) }),
  response: z.object({ events: z.array(event) }).nullable(),
});
const finding = z.object({
  finding_id: id,
  title: text,
  categories: z.array(text),
  associated_attack_ids: z.array(id),
  severity: z.object({
    band: z.enum(["Critical", "High", "Medium", "Low", "Informational"]),
    score: z.number().min(0).max(10),
  }),
  confidence: text,
  mechanism: text,
  limitations: z.array(text),
  observations: z.array(
    z.object({
      attack_id: id,
      effect: text,
      evidence: z.array(
        z.object({ attack_id: id, pointer: text, purpose: text }),
      ),
    }),
  ),
});
export const inspectAttack = (input: unknown) => attack.parse(input);
export type Attack = z.infer<typeof attack>;
export type Finding = z.infer<typeof finding>;
export type Evidence = { findings: Finding[]; attacks: Attack[] };
export function clean(value: string) {
  // All marker-bearing strings are withheld, including separator-encoded examples.
  return /syntheticcanary/i.test(value.replace(/[^a-z0-9]/gi, "")) ||
    /restricted research|internal policy/i.test(value)
    ? "[Synthetic sensitive content withheld]"
    : value;
}
export function readEvidence(): Evidence {
  const root = resolve(process.cwd(), "./fixtures/evidence");
  const manifest = JSON.parse(
    readFileSync(resolve(root, "manifest.json"), "utf8"),
  );
  if (
    manifest.schema_version !== "api-1.0" ||
    manifest.export_format !== "static-1.0"
  )
    throw Error("Unsupported export");
  function read(path: string): unknown {
    const resource = manifest.resources.find(
      (r: { path: string }) => r.path === path,
    );
    if (!resource || path.includes("..")) throw Error("Missing evidence");
    const bytes = readFileSync(resolve(root, path));
    if (
      resource.bytes !== bytes.length ||
      resource.sha256 !== createHash("sha256").update(bytes).digest("hex")
    )
      throw Error("Evidence integrity failure");
    return JSON.parse(bytes.toString());
  }
  const prefix = "scans/" + manifest.source_scan_id;
  const findings = z
    .object({ items: z.array(finding) })
    .parse(read(prefix + "/findings.json")).items;
  const listing = z
    .object({ items: z.array(z.object({ attack_id: id })) })
    .parse(read(prefix + "/attacks.json"));
  const rawAttacks = new Map(
    listing.items.map(({ attack_id }) => [
      attack_id,
      read(prefix + "/attacks/" + attack_id + ".json"),
    ]),
  );
  const attacks = listing.items.map(({ attack_id }) =>
    attack.parse(rawAttacks.get(attack_id)),
  );
  const known = new Set(attacks.map((a) => a.attack_id));
  for (const f of findings)
    for (const ref of f.associated_attack_ids)
      if (!known.has(ref)) throw Error("Broken evidence link");
  for (const f of findings)
    for (const o of f.observations)
      for (const ref of o.evidence) {
        let value: unknown = rawAttacks.get(ref.attack_id);
        if (!ref.pointer.startsWith("/"))
          throw Error("Invalid evidence pointer");
        for (const key of ref.pointer
          .slice(1)
          .split("/")
          .map((k) => k.replace(/~1/g, "/").replace(/~0/g, "~"))) {
          if (!value || typeof value !== "object" || !Object.hasOwn(value, key))
            throw Error("Missing evidence pointer");
          value = Reflect.get(value, key);
        }
      }
  // Only schema-selected fields reach the browser. Never project provenance, state or trace payloads.
  return JSON.parse(
    JSON.stringify({ findings, attacks }, (_key, value) =>
      typeof value === "string" ? clean(value) : value,
    ),
  ) as Evidence;
}
