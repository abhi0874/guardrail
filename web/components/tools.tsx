import { tools } from "../lib/catalog";
import { LiveStatus } from "./status";
const contracts = [
  [
    "{}",
    "status, service, version",
    "Protected read; strict empty-object schema.",
  ],
  [
    "query: nonblank string ≤160, limit: integer 1–5",
    "matches: approved document metadata",
    "Individual grant; policy and output screening.",
  ],
  [
    "document_id: lowercase identifier ≤48",
    "document_id, title, category, content",
    "Only approved documents; output screened.",
  ],
  [
    "title: nonblank ≤120, body: ≤1500",
    "note_id, persisted",
    "Individual grant, stable Idempotency-Key, durable audit and receipt. Unknown outcomes require operator reconciliation.",
  ],
  [
    "recipient: ops-lab or docs-lab, subject ≤120, body ≤1500",
    "simulation_id, recorded_in_memory",
    "Internal only; exact single-use operator approval.",
  ],
  [
    "url: ASCII HTTPS ≤2048",
    "host, media_type, text",
    "Internal only; host allowlist, checked numeric destination, verified TLS and bounded response.",
  ],
];
export function ToolExplorer() {
  return (
    <>
      <LiveStatus />
      <h2>Tool contracts</h2>
      <ul className="tool-list">
        {tools.map(([name, purpose, mode], i) => (
          <li key={name}>
            <details>
              <summary>
                {name} — {mode}
              </summary>
              <p>{purpose}</p>
              <p>Input: {contracts[i][0]}</p>
              <p>Output fields: {contracts[i][1]}</p>
              <p>{contracts[i][2]}</p>
              <p>
                All tools require server-established identity, rate admission,
                policy, durable audit and output checks.
              </p>
              <pre>
                {JSON.stringify(
                  {
                    name,
                    arguments:
                      name === "health"
                        ? {}
                        : name === "search_documents"
                          ? { query: "library", limit: 3 }
                          : name === "read_document"
                            ? { document_id: "public" }
                            : name === "write_note"
                              ? {
                                  title: "Synthetic example",
                                  body: "Demonstration only",
                                }
                              : name === "send_message"
                                ? {
                                    recipient: "ops-lab",
                                    subject: "Synthetic example",
                                    body: "Demonstration only",
                                  }
                                : { url: "https://example.com/" },
                  },
                  null,
                  2,
                )}
              </pre>
              <small>
                Illustrative request shape. Tool execution is unavailable in
                this website.
              </small>
            </details>
          </li>
        ))}
      </ul>
    </>
  );
}
