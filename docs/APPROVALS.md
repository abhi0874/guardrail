# Operator approval capabilities

The default policy permits health without approval. The production send_message simulation requires explicit operator approval. A permit rule that drops this requirement fails startup. Its receipt records a historical in-memory append. There is no MCP tool, HTTP route or model argument for issuing or revoking grants. A trusted operator interface must be designed before deploying approval-gated production tools.

## Issuance and binding

Trusted local code calls `ApprovalGate.issue` with a server-established authorization context, exact tool name, validated Pydantic arguments, safe issuer label and TTL of 1–3600 seconds. Issuance re-evaluates the policy and requires an approval-gated permit decision. It returns an opaque handle wrapped in `SecretStr` for trusted use. The handle contains 32 cryptographically random bytes encoded as URL-safe text. Only its SHA-256 digest is persisted. A separate UUID identifies the grant in audit metadata.

The binding includes the connection UUID, tool name, argument digest, trusted principal and roles digest, and policy snapshot digest. A single rule per tool makes the tool name and snapshot digest unambiguous. Roles are sorted and deduplicated for the identity digest. Arguments use `model_dump(mode="json")`, including defaults, serialized with sorted keys, compact separators, UTF-8, no ASCII escaping and finite JSON numbers. The canonical serializer also verifies that the wire JSON preserves the declared field values. Hidden fields, masked secrets and other lossy representations fail closed. SHA-256 covers those bytes. Equivalent key ordering yields the same binding. Changed validated values invalidate it. Argument fingerprints can reveal equality or permit guessing low-entropy values to a local reader. Protect the database as sensitive state.

## Invocation

1. Validate the arguments, establish the trusted identity and evaluate the live server's immutable policy snapshot.
2. First acquire connection and global rate tokens. For an approval-gated permit, then acquire the SQLite write transaction. In ordinary MCP use, look up the newest exact binding server-side. The agent needs only the operation arguments. An internal trusted caller can instead select a grant using its secret handle.
3. Under the write lock, check the binding, revocation, consumption and expiry. The validity window is issued time inclusive to expiration exclusive, using the trusted server clock.
4. Insert the required pre-event and policy metadata with the public grant reference. Mark the grant consumed and link it to that exact pre-event. Commit all changes together before issuing the single-use dispatch grant.
5. Run the handler and record its outcome using the original post-event boundary.

Without an exact server-side match the response is `approval_required`. A supplied trusted handle with the wrong binding or an unknown digest yields `approval_invalid`. Revocation, consumption and expiry have separate safe codes. A policy denial always wins even when a matching grant exists. A client cannot submit a privileged handle through the middleware. Explicit handles are also rejected for operations that require no approval.

Each issuance is a separate operator decision. For automatic selection the most recently issued exact match determines the result, even when it has expired or was revoked. The server does not silently fall back to an older grant. The approval authorizes one matching invocation on that connection, so competing identical requests can race for it.

## Persistence and failure behavior

The `approvals` table records issuance, expiry, optional revocation time, consumption time and consumed pre-event ID. `audit_policy` connects pre/post events to the public grant reference and policy digest. `ApprovalGate.revoke` requires the trusted handle and revokes an unused, previously unrevoked grant. It never returns a token to an MCP caller.

SQLite `BEGIN IMMEDIATE` serializes competing writers, including different store instances. A conditional update and foreign keys bind the winner to a committed audit event. A failed commit rolls back both the pre-event and consumption. No handler runs. Once the commit succeeds, a handler exception, interrupted dispatch or post-audit failure cannot make that grant reusable. For registered mutations, reservation and consumption share this transaction. A completed replay verifies the original consumed grant and the current authorization and rate admission before filtering and returning the stored public receipt. [Idempotency](IDEMPOTENCY.md)

Stored state persists across process exit. Reopening the same trusted context can use a matching unexpired grant. An ordinary stdio restart receives a new connection UUID and must obtain its own grant. Local clock and database integrity are trusted. A privileged filesystem writer or restoration of old database state is outside this guarantee.

## Tests

`tests/unit/test_approval.py` measures handler executions for replay, clock-controlled expiry, revocation, binding changes, policy denials, eight concurrent calls and a forced commit failure. `tests/integration/test_policy_stdio.py` uses the official MCP client, grants permission through a separate operator-side store, exercises health once, and verifies denial on replay and on a new connection. The separate scanner project is outside this step.

## Step 6 output failures and overload

Rate-limit denials cannot consume a fresh grant. Once admission and the dispatch fence
succeed, an output-security failure cannot restore the consumed grant or automatically
retry the write. A committed in-memory append may remain despite the denied result.
No raw approval handle enters tool output. [Rate admission](RATE_LIMITING.md) and
[output failure semantics](OUTPUT_FILTERING.md) describe these boundaries.

## Step 7 HTTP binding
Operator code uses ClientReference.authorization or HTTP_IDENTITY plus the provisioned client
UUID to issue exact grants through the existing local ApprovalGate. No HTTP issuer exists.
Authentication alone cannot approve a message. Expired/revoked capabilities fail before tool
dispatch; rate denials precede consumption. Different capabilities cannot share a grant.
Compatible completed replay verifies original approval without consuming another one.

## PostgreSQL consumption

The PostgreSQL adapter locks the selected approval row within the same transaction as
operation reservation and pre-audit. Different concurrent idempotency keys cannot spend
one grant twice. Runtime credentials cannot create schema or issue public approval
endpoints; issuance remains trusted operator code. Only digests/references are durable,
never raw handles. Simulation effects persist in PostgreSQL without changing the message
tool schema or its approval requirement. See POSTGRESQL.md.

The Cloud Phase 2 public API does not expose send_message or any approval issuer.
Browser credentials cannot supply approval or operator identity. Internal operator
workflows retain all existing approval, audit and single-use consumption guarantees.
