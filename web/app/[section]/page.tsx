import { notFound } from "next/navigation";
import { sections, type Section } from "../../lib/catalog";
import { readEvidence } from "../../lib/evidence";
import { Explorer } from "../../components/explorer";
import { SnapshotReader } from "../../components/snapshot-reader";
import { ToolExplorer } from "../../components/tools";
import { Performance } from "../../components/performance";
export function generateStaticParams() {
  return Object.keys(sections).map((section) => ({ section }));
}
export const dynamicParams = false;
export default async function Page({
  params,
}: {
  params: Promise<{ section: string }>;
}) {
  const { section } = await params;
  if (!Object.hasOwn(sections, section)) notFound();
  const data = readEvidence();
  return (
    <>
      <div className="page-head">
        <h1>{sections[section as Section]}</h1>
      </div>
      <section className="panel detail explorer">
        {section === "tools" && <ToolExplorer />}
        {section === "findings" && <Explorer data={data} />}
        {section === "tests" && (
          <>
            <SnapshotReader />
            <Explorer data={data} mode="attacks" />
          </>
        )}
        {section === "audit" && (
          <>
            <h2>Hosted denial acceptance</h2>
            <p>HTTP 409 / denied</p>
            <p>
              Phase 2I-G, revision bb465aa. One denied audit, policy and
              attempt. Notes, operations, messages and approval consumption
              unchanged. No sensitive disclosure detected.
            </p>
            <h2>Recorded synthetic execution decisions</h2>
            <p>
              These are saved Scanner trace decisions. A hosted audit-list
              endpoint is unavailable.
            </p>
            <Explorer data={data} mode="audit" />
          </>
        )}
        {section === "performance" && <Performance />}
      </section>
    </>
  );
}
