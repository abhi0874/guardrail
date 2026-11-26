export const cases = {
  health: {
    label: "Service health",
    description:
      "Call the local MCP health tool and inspect its structured response.",
  },
  document: {
    label: "Read the stdio guide",
    description:
      "Read one approved synthetic document through the MCP guardrails.",
  },
  reader: {
    label: "Restricted document",
    description:
      "Check how a reader is handled when requesting a restricted synthetic document.",
  },
  visibility: {
    label: "Internal document",
    description:
      "Check the boundary between a public reader and an internal synthetic document.",
  },
} as const;
export type CaseId = keyof typeof cases;
export type Run = {
  id: string;
  scenario: CaseId;
  at: string;
  elapsed: number;
  verdict: string;
  summary: string;
  trace: string[];
};
