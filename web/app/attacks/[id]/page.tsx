import Link from "next/link";
import { EvidenceText } from "../../../components/evidence-text";
import { notFound } from "next/navigation";
import { readEvidence } from "../../../lib/evidence";
const verdictLabel: Record<string, string> = {
  SUCCESS: "Observed success",
  BLOCKED_OR_NOT_OBSERVED: "Blocked or not observed",
  INDETERMINATE: "Indeterminate",
};
import { ReturnLink } from "../../../components/return-link";
export function generateStaticParams() {
  return readEvidence().attacks.map((a) => ({ id: a.attack_id }));
}
export const dynamicParams = false;
export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const data = readEvidence();
  const a = data.attacks.find((a) => a.attack_id === id);
  if (!a) notFound();
  return (
    <section className="panel detail">
      <ReturnLink path="/tests/" label="Back to recorded tests" />
      <h1>{a.title}</h1>
      <p>
        {a.attack_id} · {a.category}
      </p>
      <p>Recorded synthetic sandbox · {a.status}</p>
      <h2>{verdictLabel[a.detector_verdict]}</h2>
      <p>{a.definition.description}</p>
      <p>{a.definition.expected_security_boundary}</p>
      <details>
        <summary>Submitted payload availability</summary>
        <EvidenceText text={a.request.user_message} />
      </details>
      <h2>Detector evidence</h2>
      {a.detector.findings.map((f, i) => (
        <p key={i}>{f.explanation}</p>
      ))}
      <details>
        <summary>Recorded trace timeline</summary>
        <p>
          Event types and sequence are preserved. Trace payloads and state
          values are withheld.
        </p>
        <ol>
          {a.response?.events.map((e) => (
            <li key={e.sequence}>
              <code>{e.sequence}</code> {e.event_type}
            </li>
          ))}
        </ol>
      </details>
      <h2>Related findings</h2>
      {data.findings
        .filter((f) => f.associated_attack_ids.includes(id))
        .map((f) => (
          <p key={f.finding_id}>
            <Link href={"/findings/" + f.finding_id + "/"}>{f.title}</Link>
          </p>
        ))}
    </section>
  );
}
