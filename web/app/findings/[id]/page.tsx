import { notFound } from "next/navigation";
import { readEvidence } from "../../../lib/evidence";
import { FindingDetail } from "../../../components/explorer";
import { ReturnLink } from "../../../components/return-link";
export function generateStaticParams() {
  return readEvidence().findings.map((f) => ({ id: f.finding_id }));
}
export const dynamicParams = false;
export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const data = readEvidence();
  const finding = data.findings.find((f) => f.finding_id === id);
  if (!finding) notFound();
  return (
    <section className="panel detail">
      <ReturnLink path="/findings/" label="Back to filtered findings" />
      <FindingDetail finding={finding} data={data} />
    </section>
  );
}
