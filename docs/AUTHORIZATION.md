# Authorization policy v1

An MCP tool request first passes the Step 1 argument limits and strict Pydantic input schema. The pipeline evaluates the server's policy against that validated value and its server-established identity. Only a permitted operation can proceed to the approval check and durable pre-event. Registration and discovery confer no permission.

## Production policy

[tool_access.yaml](../policies/tool_access.yaml) explicitly permits `health` for the `local-anonymous` principal, with no required roles or approval. Health accepts an empty argument object. The other rules authorize local search (limit 1–5), read (approved IDs), notes, simulated messages (approved recipients and a mandatory grant) and fetch (an independent destination gate, empty by default). The policy's mandatory `default_action: deny` applies to every unlisted operation.

| Rule field | Semantics |
| --- | --- |
| tool | Exact registry name. One rule per name, no wildcards, ordering or implicit grants |
| action | permit or deny. A deny rule denies the tool unconditionally |
| principals | Nonempty list of eligible trusted principal IDs. Match any one |
| roles | All listed roles must be present. An empty list imposes no role requirement |
| constraints | All constraints must match top-level validated fields |
| approval_required | A permitted operation needs a valid grant when true |
| description | Optional operator documentation |

The application registry and policy are independent. A missing registry entry returns `unknown_tool`. A registered tool with no rule returns `tool_not_permitted`. An explicit deny returns `policy_denied`. Principal or role mismatch returns `principal_not_permitted`. Failed constraints normally return `argument_constraint_violation`. A rejected document ID returns `document_not_found`. Invalid input returns the original Step 1 error before any grant is considered. Application-visible denials retain their request IDs and safe codes when auditing is available.

## Trusted context

The stdio middleware always uses the server's `local-anonymous` identity and an empty role set. An operator label in the approval database identifies the trusted code path's declared issuer. It does not establish OS or human authentication. The per-server connection UUID groups calls on one stdio connection. A fresh server process generates a new UUID.

Client arguments, JSON-RPC metadata and strings such as `admin`, `is_admin` or `approved` cannot supply authority. Future HTTP integration must establish identity from a verified server-side source, map it to `Identity` and supply it separately from request arguments. User authentication and HTTP session handling remain Step 7 work.

## Constraint operators

All operators read named fields from the validated JSON representation actually passed to SDK dispatch. Missing fields and type mismatches fail closed.

- `equals` compares a string, integer or boolean with strict type equality.
- `one_of` accepts one of a nonempty, homogeneous list of distinct scalar values.
- `integer_range` requires an integer between inclusive minimum and maximum bounds. Booleans and numeric strings fail.

For example, a synthetic test rule can require `recipient` to equal `inbox`, restrict a category to `a` or `b`, and limit a quantity to 1–4. These tests run in-process and add no production business tools.

## Loading and changes

Set `MCP_AGENT_POLICY` to a repository-local YAML file under `policies/`. Startup parses the bounded file with PyYAML's safe loader, rejects duplicate keys, explicit tags, anchors and aliases, validates the document against [policy.v1.schema.json](../policies/schema/policy.v1.schema.json), and applies strict Pydantic checks. The checked-in contract must equal the model-generated schema. Unknown fields, versions, actions and operators fail startup, as do malformed ranges, contradictory deny/approval declarations and duplicate tool rules. There are no policy expressions, external references, scripts or network lookups.

The loader accepts up to 64 KiB and bounds container nesting. The server retains a frozen snapshot with tuple-based rules and constraints. Its SHA-256 digest covers the exact YAML bytes, including comments and whitespace. Audit records carry that digest. Changes take effect only after a restart, and approvals bound to other policy bytes no longer match. Missing or invalid configured policy produces the safe `invalid_policy` startup diagnostic.

SDK 2.3.0 remains pinned. Its middleware hook receives decoded request parameters before downstream handler lookup. Frames rejected before this hook have no application audit event. [SDK middleware documentation](https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/docs/advanced/middleware.md)

## Step 6 ordering

Current policy always precedes rate admission and receipt lookup. The limiter uses the
server-established connection UUID, never caller metadata. Screening operates only on
returned data and has no policy/approval/dispatch capability; a role claim in a document
cannot grant authority. WARN and ALLOW classify text, not permission. Every replay still
rechecks authorization before rate and output controls. See [screening](CONTENT_SCREENING.md).

## Step 7 capability principal
The shipped policy explicitly permits local-capability alongside local-anonymous, with the
same constraints and mandatory send_message approval. Only trusted HTTP authentication selects
local-capability. No capability grants operator roles. The exact policy digest changes with
this explicit principal addition; previous grants/receipts bound to old policy bytes remain
incompatible. See [SESSION_SECURITY.md](SESSION_SECURITY.md).
