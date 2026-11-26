# Cloud write responses and reconciliation

The public demo routes still invoke the official MCP client and the existing guarded
server. A successful response is produced only after the server's required durable
post-audit and completed operation receipt. No extra MCP tool or public diagnostic
endpoint is introduced.

## Response finalization

Phase 2F recorded four first-execution HTTP 503/unknown responses with four independently
verified completed notes and linked successful audit records. These remain failures of
response delivery, even though explicit later same-key recovery succeeded. The saved
Render diagnostics omit exception details and do not establish which timeout or cleanup
exception occurred in each historical request. They establish neither a readiness denial
nor an audit commit failure for those four completed operations.

Local fault injection reproduces the same effect/response mismatch with the installed
MCP 2.3.0 SDK's actual three-second request timeout. Five separate transaction-setup
requests amplified database round-trip latency across six transactions for one note
(including public session authentication). The correction sends the same five local
settings in one statement, before yielding the connection. Statement/lock/idle limits,
synchronous commit, isolation, cancellation checkpoints, pooling and TLS remain unchanged.
This removes 24 SQL requests per first note, without raising any deadline.

The broker now lists and pins all six tool schemas before dispatch and uses the SDK's
single-request session API. Metadata recovery and input callbacks cannot silently resend
a mutation. A validated successful reply is retained if transport cleanup subsequently
raises an ordinary exception. Such cleanup emits a constant warning without exception
text. Cancellation still propagates. Failed validation, an error reply or an unobserved
reply never becomes confirmed success. No partial reply is emitted.

Revision 0476fae passed bounded hosted write and restart verification. Synthetic latency
injection measures a local mechanism, not Render's database RTT, CPU share or a hosted performance guarantee. The
public four-second and internal three-second bounds remain unchanged. Free-tier sleep
and network latency can still exceed them. Readiness latency is distinct from an audited
MCP operation; a complete scan/model duration must be reported separately.

## Cross-client key conflict

HTTP 409 with `error: idempotency_key_conflict` and `outcome: denied` applies to
the current attempt. The private server has refused its binding before dispatch.
The original operation belongs to its original client. The denial returns no receipt
or details of that operation. HTTP 409 with `operation_in_progress` still has an
unknown write outcome. A lost or incomplete reply cannot establish denial.

During hosted acceptance, validate the status **and** the outcome for each attempt.
For a planned conflict, require 409, the exact conflict code, denied, and no receipt.
On any mismatch, unknown, timeout, or missing evidence, stop the whole hosted run,
including pending replay and restart steps. Preserve the original evidence and use
read-only reconciliation. A subsequent database observation cannot lift that stop.
Start a new hosted write or replay test only under separate explicit authorization.
The older Phase 2H scripts predate this rule and must not be reused as a test driver.

## Unknown outcomes

An HTTP 503 with `outcome: unknown`, a timeout or a disconnected client is not proof
that a write failed. Keep the exact grant identity, arguments and idempotency key. Never
use a new key or automatically repeat the operation. The API does not automatically
retry or expose an approval, capability, database query or general MCP endpoint.

An authorized operator must use read-only database inspection to establish:

1. The key digest matches exactly one operation, whose binding matches the original
   client UUID, tool, canonical argument digest, principal/roles digest and policy digest.
2. Its state is `COMPLETED` and its stored screened receipt identifies the actual note.
3. The original permitted pre-event and successful post-event share request/client/tool
   and policy bindings, the post references the pre, and required approval evidence is
   valid. Check actual effect rows; a receipt alone is insufficient.
4. There is exactly one corresponding effect and no unexpected approval consumption.

For a separately authorized recovery outside a stopped acceptance run, only after
this evidence is verified may the operator explicitly resend the original
request with the SAME key, arguments and identity to recover the existing receipt.
The core rechecks authorization, quotas, bindings, original audit evidence and output
screening. Recovery does not gain a new dispatch grant. A conflict, incomplete evidence,
`IN_PROGRESS` or `OUTCOME_UNKNOWN` must remain unresolved; do not reset the row, issue a
new approval/key, force success or delete evidence. An unavailable database is also
unresolved. Report the limitation and investigate with the operator.

A response cannot be guaranteed to reach a disconnected client. Confirmed server-side
success and client-observed uncertainty are intentionally distinct. Restart uses the same
PostgreSQL operation/audit records; it never clears uncertainty or repeats an effect.

## Verification and release gate

Run the real disposable PostgreSQL/official SDK regressions:

```sh
uv run --frozen pytest -q tests/cloud/test_write_response.py tests/postgresql tests/cloud
```

These tests inspect note/operation/audit/approval state for successful commits, lost
replies, storage loss before and after commit, failed post-audit, concurrent same and
different keys, readiness transitions, response delivery failure and real TCP disconnect.
Existing restart, SQLite cancellation and single-use message approval tests remain intact.
Never point test fixtures at the hosted database.

Publication, deployment, cloud settings and new hosted writes each require user approval.
The bounded retest plan and historical correlation limits are saved under the ignored
`.cache/render-write-fix/` directory. The later Phase 2H evidence is in
`.cache/render-write-release/`. Its hosted sample exceeded the 100 ms readiness target.
