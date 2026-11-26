# Resilience for asynchronous dependency calls

Step 3 provides an in-process executor for trusted handler code. The production health handler has no dependency to contact and continues to return its existing result. The production fetch_url tool executes one bounded read operation per approved hostname. [HTTPS connection and retry behavior](ADAPTERS.md)

## Security boundary

Create one `ResilienceExecutor` for the pipeline and its approved dependency names. A handler first consumes its dispatch grant using `pipeline.claim(tool_name)`. It can then call `await executor.run(Operation(name, callback, Safety.READ_ONLY))` for a genuinely read-only lookup. The executor checks the active, claimed grant on entry and before each attempt. Dependency names, callbacks and operation safety are trusted adapter configuration. Callers must not derive those choices from MCP request arguments.

An operation defaults to `UNSAFE_WRITE` and gets one attempt. Automatic retries are allowed only for explicitly read-only callbacks reporting a typed `TransientFailure`, including an executor-generated `AttemptTimeout`. Permanent exceptions, unclassified adapter timeouts, guardrail errors and caller cancellation propagate. Authorization, approval consumption, audit writes and complete tool handlers stay outside the retry loop.

The approval integration test records two denied calls (missing grant and replay), one consumed grant, one pre/post pair and one handler invocation. Only the inner synthetic read ran twice. Separate tests inject pre/post audit write failures and count both audit calls and dependency invocations.

## Ordering and time budgets

One monotonic deadline begins when the dependency operation enters the executor. It includes admission, FIFO queue waiting, all attempts and every backoff. An outer asyncio timeout also bounds suspended waits. Before every attempt the executor:

1. Checks remaining time, the claimed guardrail grant and the dependency's circuit.
2. Acquires that dependency's bulkhead slot, subject to queue capacity and wait timeout.
3. Rechecks the budget and grant, then rechecks circuit admission and reserves any recovery probe.
4. Awaits the callback inline, with a timeout bounded by the shorter of the remaining budget and the per-attempt limit.
5. Accounts for the attempt and releases capacity even if the caller is cancelled.

A typed attempt timeout is eligible for bounded read retries. `DeadlineExceeded` ends the operation. If the next delay would use up the remaining time, the executor stops immediately. The total budget never resets. Direct use of the deadline component also detects late results and a total deadline shorter than an individual attempt.

A read waits after a transient failure using the smaller of the cap and `base * 2 ** (failed_attempt - 1)`. Optional jitter uniformly samples downwards within the configured fraction of that delay. Backoff holds no slot or probe. Tests inject a clock, delay function and random samples. Real asyncio tests also exercise cancellation and timeout delivery.

## Circuit transitions

Each configured dependency owns its own circuit. State updates run synchronously within one event loop. Each transition changes a generation number so a late result from an older generation cannot change the current state.

| State | Admission and transitions |
| --- | --- |
| CLOSED | Admit normally. Successful attempts reset the consecutive transient-failure count. Reaching the threshold opens the circuit and records monotonic time. |
| OPEN | Reject immediately until cooldown elapses. The next admitted attempt starts recovery. Queued callers recheck circuit state after getting a slot. |
| HALF_OPEN | Bound the sum of successful and in-flight probes to the configured probe count. A full successful cohort closes the circuit. One transient probe failure reopens it and invalidates older completions. |

External cancellation and failures outside the transient category release probe reservations without counting as dependency outages. A later caller can replace a cancelled probe. Circuit-open, queue-full and queue-timeout errors stop immediately. Each actual transient attempt, including a retry, counts toward the breaker threshold.

## Bulkhead and cancellation

Each dependency owns a concurrent-operation limit and a bounded FIFO queue. When both are full, `BulkheadFull` rejects immediately. `QueueTimeout` reports expiration of the queue-specific wait or disabled waiting. The total deadline can end waiting earlier. On release, capacity passes directly to the oldest live waiter. A waiter cancelled between handoff and resumption passes that reservation on. The `active` and `waiting` properties expose current counts.

The executor creates no background retry or timer tasks. It awaits work in the calling task so cleanup completes before capacity is released. Callers that start their own tasks remain responsible for joining them. Cancellation is cooperative: synchronous blocking code, an adapter that suppresses cancellation forever, or remote work already accepted by an external system cannot be forcibly stopped by a Python timeout. A write timeout leaves its external outcome uncertain.

## Configuration and scope

`resilience.models.Settings` validates finite timings and bounded capacities for each dependency. Defaults are a five-second total budget, one second per attempt, two attempts for safe reads, 50 ms base backoff, one-second cap, zero jitter, three consecutive transient failures, ten seconds of cooldown and one half-open probe. The bulkhead defaults to four active calls, eight waiters and a half-second queue wait. There is no production MCP or environment control for labelling an operation retryable.

State is in memory per executor and dependency. An executor belongs to one event loop. Independent processes have independent limits and circuit state. These components provide neither cross-process coordination nor rollback. Registered mutations use the Step 3 total deadline around a single dispatch. A timed-out mutation can require reconciliation. SQLite coordinates callers across processes. [Mutation recovery](IDEMPOTENCY.md) The browser discovery skill is a separate user-level Codex tool and contributes no Python runtime dependency.

Run the focused checks with:

```sh
uv run pytest -v -s --no-cov tests/unit/test_resilience_limits.py tests/unit/test_resilience_executor.py
```

Full-suite coverage remains enforced by the normal pytest configuration.

## Step 9 verification

The [fault profile](CHAOS_TESTS.md) covers a deadline exhausted before admission, cancellation
or timeout after a committed effect, bounded read retries, open/half-open transitions and
bulkhead handoff under saturation. The [local benchmark](VERIFICATION.md) counts deadline
failures separately; its percentiles are observations rather than CI thresholds.
