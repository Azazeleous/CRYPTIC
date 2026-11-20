# Bounded ingestion runtime v2.0

The runtime module coordinates explicitly deadline-aware read-only adapters.

## Adapter contract

A participating adapter must expose deadline_enforced = True,
health_check_until(deadline_monotonic=...), and fetch_page_until(...,
deadline_monotonic=...). The adapter must pass the remaining monotonic budget
into every blocking operation: rate waits, retries, DNS/connect/read, and
pagination. Checking the deadline only before or after an unbounded blocking
call does not satisfy this contract.

Python cannot forcibly terminate arbitrary blocked threads. The coordinator
does not claim to kill non-cooperative adapters. It rejects legacy adapters
without the explicit capability and relies on the adapter's deadline-aware
transport. Process isolation may be added for untrusted extensions.

## Coordination guarantees

- Fixed worker count and bounded submitted-work window (workers + queue).
- Per-session page, observation, page-size, and monotonic-duration budgets.
- Per-source health, failure, latency, page, and observation accounting.
- Repeated cursors fail closed; raw cursors are not returned.
- Workers return pages; only the coordinator thread calls append_page.
- Journal writes are ordered by source ID and page index, not completion race.
- Final report includes journal audit and deterministic offline replay.

## Current adapter compatibility

Existing EVM and Solana adapters currently implement the legacy SourceAdapter
surface. They are intentionally rejected by v2.0 until their JSON-RPC client
and multi-call observation sequences consume a shared absolute deadline.
This prevents falsely advertising a hard session boundary.


## Deadline scope

The monotonic session deadline bounds adapter health checks and page acquisition only. Journal append/fsync, journal audit, and deterministic replay are local filesystem work performed after collection and are not forcibly interruptible by this thread-based coordinator. Their duration is measured by the surrounding caller, not claimed to be inside a hard real-time cutoff. A strict end-to-end cutoff requires a separately supervised process boundary and an explicit storage-I/O policy; this version does not claim that stronger guarantee.

## v2.0.1 accounting clarification

Worker-raised `TimeoutError` values are classified as timed-out source work,
not generic worker failures. Session reports now expose the maximum submitted
in-flight window plus collection, finalization, and total elapsed milliseconds.
The report explicitly labels the monotonic deadline scope as
`source_collection_only`; journal append/fsync, audit, and replay remain
measured finalization work and are not represented as hard-interruptible.

The in-flight metric is bounded by `max_workers + max_queue_size`. Timing
metrics are excluded from the deterministic session digest so identical
evidence does not hash differently merely because scheduling latency changed.
