# Output filtering (Step 6)

All six production tool invocations use `OutputGuard`. SDK 2.3.0 serializes the inner tool
result before `call_next` returns. Middleware passes its structured payload into the central
pipeline; the guard rebuilds both `structuredContent` and the textual content block from the
same safe object. Unchecked SDK debug text or metadata is not returned. The public Pydantic
output schema is validated after masking. Modern responses retain the current SDK server
stamp and result type. No tool input or output schema changed.

## Configuration and matching

Settings are validated at startup. The only screening profile is v1. Arbitrary regular
expressions and executable configuration are unsupported and rejected.

| Environment variable | Default | Bounds/meaning |
| --- | --- | --- |
| MCP_AGENT_OUTPUT_PROFILE | v1 | Only v1 |
| MCP_AGENT_OUTPUT_LITERALS | [] | JSON array, at most 32 printable literals, 4–256 characters each |
| MCP_AGENT_OUTPUT_PATTERNS | ["provider-key","bearer","aws-key"] | JSON array of at most three supported rule IDs |
| MCP_AGENT_OUTPUT_MAX_BYTES | 131072 | 512–1048576 compact UTF-8 result bytes |
| MCP_AGENT_OUTPUT_MAX_DEPTH | 12 | 3–32 levels, counting the root and every child value/key |
| MCP_AGENT_OUTPUT_MAX_TEXT | 32768 | 128–262144 UTF-8 bytes per string |
| MCP_AGENT_OUTPUT_MAX_ITEMS | 2048 | 16–8192 visited values/keys and bounded container lengths |

Environment arrays have a 32,768-character parsing bound. Literal configuration uses Pydantic
`SecretStr`, is excluded from repr, and serializes masked. Startup diagnostics show setting
names only. Empty literals, literals contained in the replacement marker, unknown profiles,
regex strings, non-finite limits and out-of-range values fail validation. No production
configuration contains test canaries or credentials.

Fixed patterns recognize an sk-/optional proj- credential shape (at least 16 token characters),
Bearer token syntax (at least eight characters), and 20-character AKIA/ASIA identifiers.
They do not classify every random identifier as secret. Operators select these patterns
and supply exact secret/canary values; no user-defined regex runs. Overlapping matches are
merged deterministically and replaced with `[REDACTED]`. Counts describe replacement spans,
not the number of overlapping pattern matches.

Nested JSON objects, lists and strings share the same checks. Malformed Unicode, unsupported
Python values, non-finite numbers, oversized integers, excess depth/items/text or final size
produce a safe error. Processing is bounded before large intermediate projections.
Text expansion after masking is checked too.

For production contracts only display fields named title, snippet, content and text may
change. Sensitive dictionary keys, IDs, recipient literals or other protected scalar fields
cause `output_unsafe`, rather than an invented identifier. Masking that breaks the declared
Pydantic schema also fails. The reusable `process` interface supports generic text and nested
resource data; `tool=True` enables protected-field behavior.

## Final result and errors

The final compact CallToolResult includes both structured and text copies and trusted
metadata in its byte/depth/item/text limits. JSON-RPC framing added later by the SDK, transport
whitespace and SDK allocations before middleware returns are outside this measurement.
Existing fetch streaming/body limits remain independently active.

A BLOCK screening result produces `output_blocked`; unsafe data or a filter exception produces
`output_unsafe`; bounds violations produce `output_limit`. Read failures have a failed post
event and no partial response. Fixed public error messages also pass the sensitive-text
filter; if that fails, their message is empty while the safe code/request ID remain usable.
Raw exception text is never included.

Logs contain only fixed rule IDs, counts and safe diagnostics. Audit rows contain codes and
existing bounded request summaries, never returned content or matched text. No new audit
schema or raw content column was added.

## Cache and effects

`SecuredReceipt` wraps each mutation's existing receipt codec. The projected receipt passes
screening, filtering, bounds and codec validation before any new receipt write, including
inside the local SQLite effect transaction. Raw note bodies remain exclusively in the
designated notes table as before; they are not response cache or audit content.

After dispatch, the final response is validated before the successful post-event and
COMPLETED transition. A receipt may already have safely committed before final-envelope
validation fails. Such a call does not claim success.

A failure inside a local effect transaction rolls that transaction back. An independently
committed outbox append cannot be rolled back by the output filter. After the dispatch fence,
both cases retain conservative OUTCOME_UNKNOWN semantics, consume no second approval, and
never automatically retry. An absent receipt is not proof of no effect.

Every completed replay rechecks current authorization and rate limits, verifies original
approval/evidence, then filters the historical receipt with current rules and validates the
final result. Unsafe identifiers cause a denied replay with no handler execution.
Immutable historical completed rows are not rewritten; newly configured secrets may therefore
still exist in older records that predate that configuration. This is not a database scrubber.

Detection is limited to configured exact literals and supported patterns. Unknown secrets,
split strings, encodings or data in designated business stores require separate controls.
No guarantee is made for external agents following returned text. Synthetic cache and stdio
tests verify redaction, absence in new audit/log/cache data, schema validity, changed-rule
replay, and truthful failure after an effect.
