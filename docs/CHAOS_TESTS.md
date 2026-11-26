# Local failure and recovery tests

Run the focused profile from the repository root:

    uv run --frozen pytest -qs --no-cov @tests/chaos/profile.txt

The manifest combines six new tests in tests/chaos/test_step9_faults.py with the relevant existing failure fixtures. The following 26 scenarios are distinct behaviors rather than a count of new pytest functions. The full profile collected 88 cases on the recorded run.

| # | Fault | Test boundary and verified outcome |
|---:|---|---|
| 1 | Pre-execution audit unavailable | test_audit_fail_closed and HTTP pre-event fault: dispatch denied, zero notes. |
| 2 | Post-effect audit failure | HTTP write_note fault leaves one note and withholds success; same-key retry reports unknown. |
| 3 | SQLite writer lock | test_sqlite_writer_lock_then_recovery holds a real BEGIN IMMEDIATE. No pre-event, reservation, consumed grant or effect. After rollback the original grant works once. |
| 4 | Crash before effect | test_actual_process_restart terminates a real worker at the RESERVED fence (exit 73). Reconciliation records FAILED_BEFORE_EFFECT; counter zero. |
| 5 | Crash between effect and receipt | Worker commits a separate synthetic resource DB then exits 75. Exactly one external-resource row survives with no receipt; operation is OUTCOME_UNKNOWN. |
| 6 | Crash after completed receipt | test_crash_immediately_after_completed_receipt exits 76 immediately after successful completion. Reopened scope returns the original receipt; zero new dispatches. |
| 7 | Restart of uncertain operation | The external-resource and post-local-effect (exit 74) windows reopen the same DB and reconcile past lease expiry. Two repeats cannot acquire dispatch. |
| 8 | Concurrent same key | Independent pipelines race one key. Pending/verified replay states preserve a single row, consumed grant and effect. |
| 9 | Same key, other arguments | Contention fixture counts an incompatible conflict and checks durable counter and grant count. |
| 10 | Two clients, one approval | test_racing_message_grant_isolation runs twelve competing HTTP calls with distinct keys. Only the bound client wins once. The stranger also fails to retrieve the receipt. |
| 11 | Cancel a read | Resilience executor and HTTP fetch awaiter release on cancellation; interrupted post is persisted. |
| 12 | Cancel a mutation | test_cancel_or_timeout_cannot_rerun cancels after a committed local effect. One receipt survives, state unknown, zero redispatch. |
| 13 | Deadline before/after dispatch | Inject an already expired mutation budget before admission: denied, no grant consumed or operation. Separate suspended post-effect handler times out with one durable effect and unknown outcome. |
| 14 | Retryable dependency recovers | test_retry_success_and_only_transient_reads_retry and controlled fetch retry count bounded read attempts. |
| 15 | Unsafe write fails | test_unsafe_dependency_one_attempt verifies no automatic write retry. |
| 16 | Open and recover breaker | Executor rejects repeated calls without another attempt; controlled clock and successful probe cohort restore closed state. |
| 17 | Half-open probes overlap | Concurrent held/cancelled probes, a stale result and failure generation changes are exercised in test_resilience_limits. |
| 18 | Bulkhead saturates | Bounded FIFO queue, active-slot limit, overflow, timed wait and cancelled handoff tested. |
| 19 | Quotas exhaust/refill | Clock-controlled bucket refill and concurrent admission tests, plus real transport denials before effects and approvals. |
| 20 | HTTP disconnect | Cancelling official HTTP client's pending fetch closes the exchange; server stops its read. TCP replacement preserves one note on replay. |
| 21 | Independent HTTP clients | Concurrent A/B write, replay and foreign receipt requests verified against the note/operation SQL join. |
| 22 | Capability expired/revoked | test_http_security_boundary revokes an actual capability and advances the trusted expiry clock. Both receive 401 before dispatch. |
| 23 | Fetch timeout/connect failure | test_fetch_with_resilience uses controlled connect failures and a held response; verifies retry count, breaker refusal and timeout status without Internet access. |
| 24 | Hostile retrieval under load | Two authenticated clients submit twelve reads concurrently with a failing mutation. Four hostile outputs are blocked, eight accepted outputs are redacted. |
| 25 | Redaction/audit during failure | Same workload with injected post-event fault: SQLite confirms eight successful/four failed read posts, one uncertain note, intact foreign keys. Canary absent from replies, captured logs and DB. |
| 26 | Recording interruption | Kill a real child holding a private reservation. The OS releases its lock; empty 0600 file is rejected by replay. A competing capture cannot open the occupied file; replacing an owned pathname never deletes the replacement. |

Test harnesses own isolated databases, simulated messages, temporary credentials, synthetic documents and controlled dependency callbacks. No fault injection is exposed through MCP. Crash reconciliation uses the original trusted test context; an HTTP server restart issues new credentials and does not recover a previous client's authority. Post-fence uncertainty prevents unsafe retry and does not by itself prove an effect took place. The external-resource fixture counts its own separate resource to establish the outcome. Private stale reservations may need operator cleanup.

The three Step 8 regression groups ran first, including non-finite input rejection before approval/dispatch, strict recording-version types and reservation before CLI effects. Their 16 cases passed before experiments began. See [local measurements](VERIFICATION.md) for the separate measured workloads.
