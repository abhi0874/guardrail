# Production stdio tools

Discovery returns six tools in registration order. All consume a central dispatch grant before accessing their adapter. The public schemas reject unknown arguments. The YAML policy permits the server-established local identity, applies argument constraints and requires a committed pre-event. The request ID links denials or the pre/post pair to the call.

| Tool | Input | Structured success | Execution |
| --- | --- | --- | --- |
| health | Empty object | status, service, installed version | Read |
| search_documents | Nonblank query up to 160 characters, optional limit 1–5 (default 3) | matches with document_id, title, category and snippet | Local read |
| read_document | document_id, up to 48 lowercase identifier characters | Approved document_id, title, category and content | Local read |
| write_note | Nonblank title up to 120 characters, body up to 1500 | Positive integer note_id and persisted=true | Local SQLite mutation |
| send_message | recipient of ops-lab or docs-lab, subject and body with the note limits | Opaque simulation_id, recipient and recorded_in_memory=true | Approved in-memory mutation |
| fetch_url | ASCII URL up to 2048 characters | Approved host, media_type and bounded UTF-8 text | Read with per-host resilience |

Mutation clients send the key separately in MCP request metadata, for example:

```json
{"name":"write_note","arguments":{"title":"Drill","body":"Review the runbook."},"_meta":{"mcp-agent-server/idempotency-key":"drill-01"}}
```

Use the same key for every attempt at the same logical action. The response metadata field `mcp-agent-server/replayed` distinguishes the initial result from a cached receipt. Completed replays recheck current authorization, rate limits, original approval evidence and current output rules. A different connection, principal, tool, policy digest or argument fingerprint cannot reuse the result. A new stdio process normally establishes a new connection UUID. Keep synthetic note text in the server-managed notes table. Operation receipts and audit rows exclude the text.

To exercise `send_message`, a trusted local operator calls `ApprovalGate.issue` with the trusted connection, current policy, a validated `Message` and a bounded TTL. The server selects the exact grant under the SQLite write lock. New execution consumes it once alongside the pre-event and reservation. The caller cannot issue grants through MCP. The outbox appends a local simulation only. Nothing is sent to a provider. Its list disappears on process exit. A durable receipt attests only to the earlier append, even if replayed after the outbox has disappeared.

Run `uv run pytest -qs --no-cov tests/integration/test_production_tools.py` for an official-client demonstration with isolated state and a controlled fetch transport. The test reads the SQLite rows and counts the actual in-memory entries.

Document and HTTP responses are untrusted data. Step 6 applies content screening, output filtering and rate limiting to all six tools, including completed replay. Stdio remains the default; Step 7 adds opt-in local Streamable HTTP. Scanner integration belongs to Step 11. The server requires no LLM or credentials.

## Step 6 result metadata

The structured schemas above are unchanged. Successful results add safe
mcp-agent-server/output metadata: source, profile, disposition, rule IDs and redaction count.
Health and mutation receipts are checked too. Documents, snippets and fetched text may be
masked in display fields or refused; IDs are never silently changed. Both textual and
structured MCP representations agree. Existing fetch body, TLS, destination and resilience
controls remain active. No public resources were registered. See
[OUTPUT_FILTERING.md](OUTPUT_FILTERING.md) for configuration and [RATE_LIMITING.md](RATE_LIMITING.md)
for admission budgets.

## Step 7 transport parity
The same six schemas are served over opt-in local Streamable HTTP and default stdio.
HTTP requires a local capability; messages additionally require exact operator approval.
Search, read, health, notes/replays, message simulation and fetch denial are tested using the
official client against a real loopback listener. Allowed fetch tests use controlled adapters.
