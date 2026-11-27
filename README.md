# Guardrail

Guardrail includes an MCP server with authorized tool calls, an Agent Security Scanner that evaluates recorded evidence, and a recorded dashboard for exploring synthetic results.

| Component | What to try |
| --- | --- |
| MCP Agent Server | Run a synthetic stdio walkthrough, inspect an authorized document read and verify idempotent writes and denials. |
| Agent Security Scanner | Evaluate constructed observations, compare the detector against its frozen synthetic benchmark and inspect the evidence contracts. |
| Dashboard | Explore four walkthroughs, 42 historical result summaries and four findings. Filter recorded evidence and step through trace events. |

## Run locally

With Python 3.11.18 and uv installed, start at the repository root.

```sh
uv sync --frozen --python 3.11.18
uv run --frozen python -m mcp_agent_server.agent demo
```

For the Scanner walkthrough and benchmark, use the [Scanner instructions](security-tests/scanner/README.md).

With Node 26 installed, start the dashboard from the same checkout.

```sh
cd web
npm ci --ignore-scripts
npm run dev
```

Open the local address printed by Next.js. Use `npm run lab` to run the four fixed local operations against disposable synthetic state. The default dashboard replays their saved results. Both modes use synthetic data. The public dashboard has no live account functionality.

See [architecture](docs/ARCHITECTURE.md), [verification](docs/VERIFICATION.md), [deployment status and known limitations](docs/DEPLOYMENT_STATUS.md), and [licensing](LICENSING.md).

## Hosted demonstrations

- [Hosted Guardrail dashboard](https://mcp-agent-security.vercel.app) presents recorded results and separately operated live account features.
- [Recorded recruiter demo](https://guardrail-mcp-security-lab.vercel.app) presents standalone synthetic walkthroughs.
