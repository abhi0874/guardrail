import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { readCounts } from "./snapshot";

// Called during static generation only. Neither paths nor resource names come from a request.
export function scannerSnapshot() {
  const root = resolve(process.cwd(), "./fixtures/evidence");
  const manifest = JSON.parse(
    readFileSync(resolve(root, "manifest.json"), "utf8"),
  );
  const bytes = readFileSync(resolve(root, "overview.json"));
  const resource = manifest.resources.find(
    (r: { path: string }) => r.path === "overview.json",
  );
  const source = JSON.parse(bytes.toString("utf8"));
  if (
    manifest.export_format !== "static-1.0" ||
    manifest.schema_version !== "api-1.0" ||
    source.schema_version !== "api-1.0" ||
    source.scope !== "local_synthetic_sandbox" ||
    resource?.bytes !== bytes.length ||
    resource?.sha256 !== createHash("sha256").update(bytes).digest("hex")
  )
    throw new Error("Scanner export integrity check failed");
  return readCounts(source.counts);
}
