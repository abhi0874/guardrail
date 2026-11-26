# Rate limiting (Step 6)

Every authorized production tool call, including completed replay, must acquire one token
from both its trusted connection bucket and the process-global bucket. Discovery and other
SDK protocol traffic are outside this tools/call quota. The generated stdio connection UUID
is a server-established grouping, not authenticated user identity. Client principal,
connection or session metadata cannot select a bucket.

## Configuration

| Environment variable | Default | Allowed range |
| --- | --- | --- |
| MCP_AGENT_RATE_CONNECTION_CAPACITY | 100 | 1–100000 tokens |
| MCP_AGENT_RATE_GLOBAL_CAPACITY | 1000 | 1–1000000 tokens |
| MCP_AGENT_RATE_CONNECTION_REFILL | 20 | 0.001–100000 tokens/second |
| MCP_AGENT_RATE_GLOBAL_REFILL | 200 | 0.001–1000000 tokens/second |
| MCP_AGENT_RATE_MAX_CONNECTIONS | 1024 | 1–8192 buckets |
| MCP_AGENT_RATE_RETENTION | 300 | 1–86400 seconds idle before eviction eligibility |

Negative/zero capacities, zero/non-finite refill rates and pathological values fail startup.
Defaults allow ordinary local demos. Rate limiting has no disable switch. Isolated tests use
small capacities and a deterministic clock.

At time t a bucket has `available = min(capacity, tokens + (t - updated) * refill)`.
Admission requires available >= 1 in both buckets. Only acceptance atomically stores both
new token counts and timestamps. A denied combined admission consumes neither quota.
Backward clock values are clamped to the last accepted global timestamp. Non-finite clock
values deny safely. Tokens never become negative.

The async admission method has no token wait, retry or await inside its short synchronous
mutex. One process lock coordinates even concurrent callers from different threads/event
loops. State contains at most MAX_CONNECTIONS entries. On capacity pressure it evicts only
buckets that are both idle for RETENTION and completely replenished. A partially filled
bucket cannot be evicted to reset its quota. If no slot is available the call is denied.
Cleanup is bounded by the configured maximum; there are no background workers.

The production factory shares a process-global limiter across server instances. Conflicting
limiter settings in one process fail configuration rather than silently creating a new quota.
Trusted standalone Pipeline test instances can receive an isolated limiter. Multiple
connections share the global cap. Separate processes have independent state and restarting a
process resets its quotas; this is not distributed rate limiting.

## Ordering and evidence

Strict validation (including mutation key format) and current authorization precede rate
admission. Rate admission precedes approval lookup/consumption, idempotency reservation or
replay lookup, pre-event persistence and business dispatch. A rate denial therefore cannot
consume an approval, create an operation, insert a note or append a message. Quota accepted
before a later approval/idempotency/audit failure is not refunded; rate limiting bounds
authorized attempts, not only successful effects.

A visible denial persists a denied audit event when storage is available. Failure of that
audit produces audit_unavailable and still never dispatches. No queue or hidden retry is
introduced. Errors carry rate_limit_exceeded, retryable=true, a fresh request ID and a fixed
category message: connection, global, connection capacity or clock. No private ID is
included and no speculative retry-after duration is reported.

Unit tests verify burst/refill/backward time, combined rollback, independent connections,
bounded retention, and both async and thread concurrency. Stdio tests forge identity metadata,
exhaust note replay capacity and check actual approval/operation/note/outbox counts.

Step 7 must establish trusted HTTP connection/session lifecycle before reusing this interface.
This step adds neither HTTP listeners nor sessions, authentication, Redis or a coordinator.

## Step 7 client buckets
Authenticated HTTP capabilities supply the UUID used for local buckets; stdio uses its
server-instance UUID. Both share the process-global limiter. TCP replacement, forged metadata
or headers cannot select a fresh bucket. A trusted operator can issue another capability,
still subject to the global quota. Limits remain process-local. See SESSION_SECURITY.md.
