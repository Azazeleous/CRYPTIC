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
