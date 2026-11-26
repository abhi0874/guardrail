# Adapter boundaries

## Documents and notes

Four synthetic documents ship as frozen, bounded Python records. Their IDs are `stdio-guide`, `retry-policy`, `incident-runbook` and `approval-guide`. Reads use an exact ID lookup. An ID never becomes a path or an external query. The policy separately enumerates the approved IDs. Search splits case-folded words, counts each distinct query word's occurrences in a title at weight three and in content at weight one, excludes zero scores and breaks ties by document ID. Snippets contain up to 180 characters of the approved content.

Schema v4 adds a `notes` table to the existing database. It migrates the exact v3 layout in the same transaction as the schema version change. A note insert uses bound parameters and returns its database ID. The insert and safe receipt share the Step 4 local-effect transaction. A failed pre-event prevents insertion. If the later post-event fails, the committed note can still exist. The client receives an audit-integrity error and a duplicate cannot write it again.

The message adapter stores a validated synthetic message and a random simulation receipt in the server process. Only a tightly validated 32-character hex ID, synthetic recipient and recording flag enter the replay cache. The append and durable outcome are separate operations. Process death between them can leave an unknown outcome. An operator must reconcile it; automatic writes never retry.

## HTTPS egress

`MCP_AGENT_FETCH_HOSTS` is empty by default. An operator can configure comma-separated exact ASCII DNS names, such as `docs.example.org`. Each entry permits HTTPS GET on port 443 for that host, including paths and queries. Select only hosts whose entire permitted HTTPS surface is appropriate. The parser excludes IP literals, wildcard and internationalized names, local suffixes, alternate numeric spellings, credentials, fragments and ambiguous authorities. No caller-supplied headers, proxy, TLS settings or method are accepted.

Every admitted attempt resolves the exact absolute DNS name. It rejects the complete answer set if any address is unsafe. Validation excludes non-global addresses, shared IPv4 space, special ranges, multicast, mapped IPv6, scoped addresses and IPv6 transition ranges. The request URL is reconstructed with the checked **numeric address**. HTTPX's native async transport sends this address as the TCP origin. Its httpcore `sni_hostname` extension carries the original allowlisted hostname for TLS hostname checking and SNI. The HTTP Host header is set by the adapter to that name. The client and transport both disable environment trust. Each attempt owns its own transport and connection pool. Resolving the original name again cannot change the TCP peer selected for that attempt.

Redirects are disabled and every redirect status is rejected. The adapter accepts HTTP 200 with text/plain or text/markdown, optionally UTF-8. It requests identity encoding, rejects compressed or binary responses, checks a 16,384-byte limit while streaming raw bytes, and requires strict UTF-8. There is no disk download or cookie jar shared across attempts. The adapter does not evaluate response text.

The Step 3 executor bounds DNS, connection, TLS, headers and streaming with one five-second total budget and one-second attempt budgets. Transient network failures, timeouts and 502/503/504 responses are eligible for at most two attempts. Each approved host has its own circuit and FIFO bulkhead. Policy and URL denials precede retrieval. DNS safety, content and size denials have no automatic retry. The security suite injects controlled DNS and a simulated stream below HTTPX/httpcore to observe the actual TCP host, verified TLS parameters and HTTP Host. The official MCP demo uses an offline mock transport. Neither performs a live public fetch.

## Validation scope

`uv run pytest -q --no-cov tests/security/test_fetch_url.py` exercises parsing, rebinding, redirects, streaming and dependency faults. Default tests work offline. The database, operator configuration, host routing, resolver and public certificate trust store are trusted deployment components. A permitted public endpoint can serve malicious text or proxy other services itself. Operators control this exposure by choosing dedicated destinations. Deployment hardening and live endpoint validation are outside this step.
