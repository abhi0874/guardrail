export const sections = {
  tools: "MCP tools",
  tests: "Security tests",
  findings: "Findings",
  audit: "Audit evidence",
  performance: "Performance",
} as const;
export type Section = keyof typeof sections;
export const release = {
  sha: "bb465aa",
  mcp: 933,
  scanner: 325,
  coverage: "96.61%",
} as const;
export const tools = [
  ["health", "Service health", "Protected read"],
  ["search_documents", "Search approved documents", "Protected read"],
  ["read_document", "Read an approved document", "Protected read"],
  ["write_note", "Persist a synthetic note", "Protected write"],
  [
    "send_message",
    "Simulate a message with operator approval",
    "Internal only",
  ],
  ["fetch_url", "Retrieve an allowlisted resource", "Internal only"],
] as const;
