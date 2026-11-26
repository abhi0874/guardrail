# Idempotent mutations

The production write_note and send_message tools use this mechanism. This boundary prevents a duplicate delivery with the same key from acquiring a second dispatch right in the same database.

## Request and scope

A future mutation must have a strict application argument schema, a policy rule, a `Mutation` registration on the pipeline and a bounded set of public receipt fields. The operator issues any required grant through the existing internal gate. The MCP client sends the key in `_meta["mcp-agent-server/idempotency-key"]`. Use 1–96 ASCII letters, digits, underscores or hyphens, case-sensitive. Whitespace, slashes, controls, empty strings and Unicode are rejected. Generate opaque keys without secrets. Only the SHA-256 digest is stored.

The server validates arguments and the key, then checks the current frozen policy on each request. A global unique digest binds the first reservation to the server-established connection UUID, hash of principal and sorted distinct roles, tool, validated-argument hash and exact policy-file digest. Caller arguments and metadata cannot select a principal or session. A permitted but incompatible context receives `idempotency_key_conflict`. Policy or rate denial wins over a cache lookup.

Step 2's canonical serializer orders object keys, preserves list order, emits compact UTF-8 JSON and includes model defaults. Unicode code points remain distinct without normalization. Booleans, null, integers and finite floats retain their JSON representations. Declared values and the Pydantic JSON representation must match. Non-string object keys, non-JSON types, malformed Unicode, nonfinite numbers and lossy serializers fail validation. Hashes reveal equality to a database reader.

## Database and dispatch

Schema v3 migrates the exact v1 or v2 layout under a single SQLite write transaction. Historical audit and approval rows keep their keys. The `operations` table contains a generated operation ID, original request ID, binding, state, pre/post event references, timestamps, expiry, receipt and safe error code. `operation_attempts` links each idempotency decision to its own audit event and original operation. Requests denied before identifying an operation have ordinary denied audit events. The state trigger rejects invalid transitions and updates to completed rows.

1. Under `BEGIN IMMEDIATE`, look up the unique key. For a new operation, consume the required grant, insert the pre-event and reserve the key. Commit before exposing the single-use dispatch grant.
2. Only the owner with the internal operation ID can conditionally advance `RESERVED` to `IN_PROGRESS`. The handler claims its invocation before starting work. Independent processes and tasks share the database uniqueness constraint. Compatible competing callers get `operation_in_progress` or a completed replay. The SQLite admission lock wait is bounded by the smaller of the remaining execution budget and two seconds.
3. A trusted local transaction callback can use `MutationService.local_effect` inside the claimed handler. Limit the callback to bounded synchronous SQL on the supplied connection. The store owns commit and rollback. The effect and a projected receipt commit together. The test fixture uses SQLite's transactional application ID as a counter so it can verify the persisted value without adding a business table to the production schema.
4. For an independently committed resource, record the observed safe receipt after dispatch returns. The receipt and effect can be separated by a crash. On success, commit the original post-event and the `COMPLETED` transition together. Send the client response after commit.

## States and recovery

| From | To | Evidence |
| --- | --- | --- |
| New key | RESERVED | Approval, pre-event and reservation committed together |
| RESERVED | IN_PROGRESS | One owner crossed the dispatch fence |
| RESERVED | FAILED_BEFORE_EFFECT | Owner stopped or reservation expired before crossing the fence |
| IN_PROGRESS | COMPLETED | Safe receipt and correlated successful post-event are durable |
| IN_PROGRESS | OUTCOME_UNKNOWN | Dispatch interrupted, deadline expired, audit integrity failed or in-progress owner expired |

All three terminal states retain the key. The store never automatically grants another execution for it. A compatible authorized duplicate reconciles an expired reservation under the SQLite write lock. Expiry is persisted wall-clock time at admission plus the mutation budget and five seconds of grace. Starting another server alone does not invalidate a live owner. The reconciliation decision, interrupted post-event and requesting attempt are recorded together. A late owner's conditional completion cannot supersede a recovery decision. The deployment must trust its wall clock, database and filesystem.

For `operation_outcome_unknown`, inspect the original audit events, receipt and any independent resource evidence before deciding on another action. A receipt can establish that an effect occurred even when the post-event failed. An absent receipt leaves external delivery unresolved. Clients must keep the original key across retries. A fresh key authorizes a separate operation and must never be used as automatic recovery. Manual reconciliation is an operator responsibility. Production contains no public reset or reconciliation tool.

## Replay and failure reporting

A completed replay checks current policy, rate admission and exact scope. It verifies the original permitted pre-event, the new-operation decision, the matching successful post-event and policy metadata. For gated operations it verifies the exact consumed approval, original validity interval and binding. Only then does it return a validated stored receipt and audit the replay. The handler stays idle and no further approval is consumed. The MCP response includes `_meta["mcp-agent-server/replayed"]` and uses the negotiated result envelope. Current stdio connections receive fresh UUIDs on reconnect. Replay after a service restart needs the same established trusted scope. A new stdio connection cannot display an old connection's result.

Tool authors must explicitly allowlist public integer or boolean fields. Receipts are limited to 4 KiB and integers to the interoperable JSON range. The message-specific codec also permits a fixed-format hex ID and one of two synthetic recipient literals. Only the projected receipt is returned, including on the first call. Raw inputs, free text, SDK debug content, credentials and bearer handles are excluded. This is a narrow receipt contract. Step 6 wraps these codecs with screening and filtering before storage and on replay; see [OUTPUT_FILTERING.md](OUTPUT_FILTERING.md).

The Step 3 monotonic budget includes admission and dispatch. The handler runs once, with cooperative cancellation. Bounded SQLite settlement and durable failure reporting can extend response latency beyond the dispatch deadline. The dependency executor still permits bounded retries for declared reads. Writes use `Safety.UNSAFE_WRITE` and one attempt. A circuit breaker, bulkhead or client retry cannot acquire another dispatch for the same key.

A failed admission transaction rolls back the reservation, grant consumption and pre-event. A post-audit failure returns `audit_integrity_failure`; any committed receipt is retained, and an independent transaction records uncertainty if storage is available. When the store itself is unavailable, the last committed state determines recovery after reopening. Secrets, exception messages and raw SQL stay out of client errors. Recovery can establish at-most-one admission per retained key. It cannot establish universal exactly-once delivery to external systems or compensate for loss, rollback or hostile replacement of the database.

## Verification

From the project root:

```sh
uv run pytest -s --no-cov tests/unit/test_idempotency_models.py tests/integration/test_idempotency_*.py tests/integration/test_state_change_pipeline.py
uv run pytest -s --no-cov tests/integration/test_mcp_stdio.py
uv run pytest --cov=src/mcp_agent_server --cov-report=term-missing
```

The recovery tests terminate a child process before dispatch, after a local effect and receipt, and after an independent resource commits before a receipt exists. They reopen the original database, check persisted effects and verify zero new handler calls. The concurrency tests count actual invocations, consumed grants and counter changes across independent store instances.

## Step 6 safe persistence

SecuredReceipt validates and sanitizes every new projected receipt before storage, including
inside local_effect. Final-envelope validation precedes successful completion. Historical
completed rows remain immutable; current filtering can redact a replay or deny an unsafe
identifier without dispatching again. Old rows are not retroactively scrubbed.
Rate denial creates no operation_attempt or reservation; it has an ordinary denied event.
See [OUTPUT_FILTERING.md](OUTPUT_FILTERING.md) for the local rollback/external-effect distinction.

## Step 7 HTTP replay
A legitimate capability retains its binding across successive HTTP requests and TCP reconnects.
Each request still rechecks authentication, authorization, rate admission and current output
rules. Another capability cannot retrieve the receipt. Restart invalidates capabilities; no
automatic context restoration or mutation retry is introduced. Disconnect/audit failure can
leave uncertainty; use the original key and reconcile actual effects before a new operation.

## Step 9 crash and contention checks

A real child exits just after durable completion. Reopening its established test scope yields
the original receipt and no second dispatch. A separate child commits an independent resource
and dies before receipt persistence: recovery remains uncertain. Same-key contention checks
SQL effect counts under load. See [crash windows](CHAOS_TESTS.md) and [replay timings](VERIFICATION.md).

## PostgreSQL persistence

PostgreSQL uses a transaction-scoped digest lock for absent-key admission, unique keys,
row locks for effect/recovery decisions and a native state-transition trigger. Notes and
durable message simulations share the operation receipt transaction. Verified replay
creates no new effect and consumes no new approval. Broken connections are replaced
before future transactions; an uncertain transaction is never re-executed. SQLite retains
its original BEGIN IMMEDIATE contract. See POSTGRESQL.md for migration and restore rules.

Cloud demo clients have operator-owned durable UUID bindings; browsers cannot select
or replace these IDs. A write's Idempotency-Key is forwarded unchanged through the
official client. Timeout/disconnect responses stay unknown and never trigger an automatic
retry/new key. Restart and credential rotation for the same trusted UUID preserve scope.
