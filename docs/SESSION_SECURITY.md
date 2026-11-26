# Application client context and capabilities

MCP 2026-07-28 is sessionless. This application retains trusted client context for policy,
approval, idempotency, audit correlation and rate admission independently of MCP sessions,
HTTP connections and client-supplied metadata.

## Issuance and trust

Clients.issue is an internal operator API. It generates 32 cryptographically random bytes
encoded as an opaque 43-character URL-safe capability, returns it as SecretStr, and stores
only its SHA-256 digest in the process registry. A separate random UUID identifies the client.
The UUID is public correlation, not a credential. All HTTP capabilities have the fixed
local-capability principal with no privileged roles. The default policy explicitly allows
this principal for the same six operations as stdio; send_message still requires approval.
Stdio retains its local-anonymous principal and generated connection UUID.

The HTTP CLI starts without a configured secret. It creates a random-named client JSON file
inside .runtime/http (0700), with mode 0600 and exclusive creation. Directory symlinks and
insecure directory modes/ownership fail startup. The file holds the capability, public
client reference and TTL. Only its filename is logged. Keep this file private; never paste
its token into shell commands, source, logs or ordinary MCP tool arguments.

A trusted local launcher can create Clients, call issue multiple times, construct
create_server(settings, http_context=clients.resolve), and wrap it in HTTPApplication.
The wrapper refuses a server lacking the matching resolver. Issuance/revocation are never
MCP tools, HTTP routes or actions available to a remote client. The operator can call
clients.revoke(reference.identifier); clients.clear invalidates all capabilities.
The CLI's single initial client is intentionally minimal. Additional client provisioning
and live individual revocation use a trusted launcher; there is no remote management API.

## Approval and stable scope

Trusted operator code issues a grant with reference.authorization, a validated Message,
the current policy and the existing ApprovalGate. In a separate local operator process,
construct AuthorizationContext with HTTP_IDENTITY and the private file's public reference,
using AuditStore and load_policy. Possession of filesystem/operator access is explicitly
trusted; an ordinary HTTP caller has no access to this mechanism.

HTTP authentication proves possession of a local capability, not a human identity or
administrator role. Authentication does not issue or consume an approval automatically.
The guardrail pipeline uses the trusted UUID for connection/client binding. Each invocation
still has its own request UUID. Altering MCP arguments, _meta, X-Client-Id, role/session
headers or forwarded headers cannot change the trusted context.

Successive requests and new TCP connections carrying the same capability retain the UUID.
Different capabilities never share approvals or replay scope. Original consumed grants
remain single-use; compatible completed message replay returns the historical receipt
without another append. Cross-client cached-result requests fail the existing binding check.

## Expiry, memory and restart

Capabilities have a monotonic expiry (default one hour), bounded by configuration. Authentication
removes an expired matching entry; issuance prunes all expired entries before checking capacity.
At capacity issuance refuses rather than evicting live clients. State is bounded, guarded by
a lock, and uses no cleanup worker. Revocation removes matching entries immediately.
Tool middleware revalidates the scope reference after body processing, including expiry and
registry membership. Already admitted work may finish; revocation does not promise rollback.

The scope reference is injected by the ASGI wrapper as a Python object, never reconstructed
from caller IDs. Each request uses a copied scope. No mutable global current-client variable
or shared identity ContextVar is used. Concurrent requests receive independent request IDs
and retain their capability's identity through SQLite and dispatch.

Shutdown invalidates all capabilities. Restart produces a new registry and new client UUIDs.
Old tokens and approvals cannot authenticate/replay automatically. After a crash, a stale
private credential file may require manual removal, but it grants no access to the restarted
process. Reconciliation of uncertain effects remains an operator responsibility.

## Audit and rate semantics

Existing schema v4 is retained. HTTP events store the trusted client UUID in connection_id,
local-capability in audit_policy.principal, and an explicit transport=streamable-http prefix
in the bounded argument_summary. No caller strings are added. Request IDs, phase, tool,
policy digest and operation/pre/post correlations retain their original fields.
Historical/stdio summaries are unchanged and have implicit stdio transport.

Per-client rate admission uses the trusted UUID; the process-global bucket is shared with
every server instance in that process. Reconnecting or changing headers cannot reset it.
Issuing a new capability requires the operator and still cannot bypass the global bucket.
Combined denial consumes neither bucket and precedes approval/reservation/effects.

Transport rejection is outside SQLite tool auditing. SDK/library diagnostics use the existing
JSON formatter and suppress untrusted library message bodies, not logging failures.
Capability/approval secrets and raw sensitive outputs are excluded from diagnostics and audit.

## Limitations

The filesystem owner and trusted launcher are privileged. Other processes with the same
OS user's file access can obtain a stored capability; this is not OS-user isolation.
Stolen capabilities impersonate their client until expiry/revocation. Loopback alone is not
authentication. There is no OAuth, remote identity, TLS, multi-worker synchronization or
distributed rate limit. HTTP is restricted to 127.0.0.1 for this step. External agents must
still treat tool content as untrusted; this step adds no LLM or Scanner integration.
