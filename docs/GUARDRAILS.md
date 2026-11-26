# Tool dispatch through Step 6

Every successfully dispatched application tool handler must pass through strict validation and a committed pre-execution audit event. The stdio server publishes six tools. The health schema has no input fields. Health's successful structured output still comes from the installed package metadata.

## SDK boundary

The server installs `ToolMiddleware` through the public `MCPServer(..., middleware=[...])` API. In the pinned SDK, the runner supplies decoded method, params, request ID and protocol version before its own method-specific validation and lookup. The inner `call_next(ctx)` returns the serialized wire result. This lets the application refuse a request before SDK dispatch and inspect its result afterward. The SDK marks this hook provisional. Reverify these behaviors and run the stdio suite before upgrading. [SDK 2.3.0 middleware documentation](https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/docs/advanced/middleware.md)

1. Discovery and other protocol traffic continue through the SDK. For a `tools/call` request, the middleware creates a fresh application request UUID. One generated connection UUID groups calls to this stdio server instance. Client metadata, caller-supplied IDs and identity claims do not supply audit identities.
2. The pipeline looks up the application's schema by tool name. Only trusted registered labels enter storage. Unknown names are recorded as `<unknown>`. The application schema registry and YAML permissions are separate. The shipped policy has one explicit rule for each of the six tools.
3. For a known tool, validation checks the compact UTF-8 JSON byte budget and container depth, then runs strict Pydantic validation. The policy checks the trusted identity and validated arguments. A visible rejection writes one denied event. A permitted request must acquire both rate tokens, then commit its pre-event before it receives a task-local dispatch grant. When approval is required, its consumption and the pre-event commit together.
4. The middleware supplies the validated argument object to the remaining SDK chain. The registered health function must consume its single-use grant before it can run business code. Even a direct in-process call via the SDK's public `call_tool` method cannot run that business code without a grant. A new SDK tool registration alone does not enter the application's registry or permission list.
5. The pipeline revokes the grant, screens, filters and validates the result, then records the outcome and returns the rebuilt safe result only after post-event persistence. Nested or repeated claims fail. Programmatic calls outside transport middleware do not create inbound-request audit events.

## Validation semantics

Omitting the argument member gives the SDK's no-argument convention, equivalent to `{}`. Explicit null, lists at the root, unknown fields, non-string keys, non-finite floats and non-JSON Python values fail. Per-tool models use `extra="forbid"` and validation runs in strict mode. In particular, a string or boolean cannot stand in for a strict integer in a future schema.

`MCP_AGENT_MAX_ARGUMENT_BYTES` measures compact JSON bytes including punctuation, UTF-8 and escaping, with a default of 8192. `MCP_AGENT_MAX_ARGUMENT_DEPTH` counts containers, with the root object at depth one and a default maximum of eight. These checks bound application processing of decoded arguments. They do not measure wire whitespace, the whole JSON-RPC envelope, or memory already allocated by the transport. The application never evaluates argument strings.

## Denial and failure semantics

Middleware refusals use a real SDK `MCPError`. Its public data contains `code`, a fixed safe `message`, `retryable` and the application `request_id`. Invalid arguments use JSON-RPC -32602. Other guardrail failures use the server error range (-32000). Rate-limit errors have `retryable=true`; other guardrail error contracts retain their existing retry semantics. A host can continue to call the server after a denial.

| Public code | Meaning |
| --- | --- |
| invalid_tool_arguments | Arguments violate the strict schema, JSON type or depth limit |
| request_too_large | Encoded arguments exceed the configured budget |
| unknown_tool | Application registry has no entry for this name |
| tool_not_permitted | No matching policy rule or valid dispatch grant |
| audit_unavailable | The audit record required before dispatch could not commit |
| tool_execution_failed | SDK dispatch raised or returned a tool error. The client receives a fixed error instead of exception text |
| audit_integrity_failure | The required post-event failed. Dispatch may already have had an effect |

`dispatch_failed` describes the downstream SDK call. That call includes SDK validation, handler execution and serialization, so the status alone cannot establish which substage failed. The server logs safe diagnostic messages to stderr. Model error values and traceback details are excluded.

## Visibility and future work

Tests send unexpected fields, deep and oversized objects, and unknown tool names through an actual SDK client. The middleware sees and audits those requests. A malformed non-JSON frame sent to the real server produced no tool event. A client may also reject input locally. The application cannot audit a request that never reaches its hook. SDK lookup, decoding and middleware order are version-specific.

This boundary trusts the local process, its installed code and its configuration. Access to the stdio pipes currently confers access to health. The generated connection identifier carries no authentication meaning. See [AUTHORIZATION.md](AUTHORIZATION.md) for policy matching and [APPROVALS.md](APPROVALS.md) for approval errors, consumption and correlation. Step 6 rate and output controls are described below.

Production tool handlers must claim their own dispatch. Typed adapter failures are reduced to fixed codes, correlated with a post-event and surfaced as structured MCP errors. [Tool contracts](TOOLS.md)

## Step 6 enforcement

Output blocking/unsafe/limit errors withhold the complete result; read post-events record
dispatch_failed. Mutation failures after dispatch retain uncertain-outcome semantics.
Current output rules also cover completed replay. Every six-tool registration is wired
through this boundary and Pydantic output schema validation. The original SDK text/meta
is replaced with the safe projection, provenance and trusted protocol stamp.
Rate denials precede any approval or reservation and use a safe category with retryable=true.
See [output filtering](OUTPUT_FILTERING.md) and [rate limiting](RATE_LIMITING.md).

## Step 7 HTTP entry
HTTPApplication enforces transport security and a local capability before SDK validation.
ToolMiddleware receives a trusted context resolver; HTTP wrapping without that matching
resolver is rejected. Client metadata cannot set principal or connection ID. Request UUIDs
remain per-call, while the trusted capability UUID survives TCP reconnects. All six tools
use the unchanged security/output path. See [HTTP_TRANSPORT.md](HTTP_TRANSPORT.md).
