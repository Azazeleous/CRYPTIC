# ADR-0021: Supervised whole-request HTTP transport

- Status: proposed for review
- Date: 2026-11-20
- Scope: read-only JSON-RPC transport deadlines

## Context

The v2.1 deadline propagation bounded rate-gate waits, retry backoff, and socket timeout selection. PR #20 added an isolated DNS resolver foundation, but the existing JSON-RPC client still performed the complete urllib request in the coordinator process. A blocking resolver or a response body that trickles bytes can outlive a socket-operation timeout. Therefore those earlier controls did not prove a hard deadline for the complete request.

## Decision

Use one supervised, spawn-based HTTP worker per JSON-RPC client.

- The worker is started and handshaken by adapter preparation before the runtime starts its collection deadline.
- The complete request runs in the worker: name resolution, TCP connection, TLS negotiation, HTTP exchange, headers, and response-body read.
- The original HTTPS URL hostname is retained. The standard-library HTTPS handler performs normal certificate-chain and hostname verification and supplies the hostname for SNI.
- Redirects are not followed. A redirect status is returned to the parent and treated as a non-retryable HTTP status.
- The worker reads at most max_response_bytes + 1; the parent parser rejects a response exceeding the configured cap.
- The parent waits on IPC only for the remaining absolute monotonic deadline. If the wait expires, it terminates (then kills if necessary) the worker and permanently poisons that worker instance.
- A poisoned worker is not restarted during the active collection. The owning session fails closed; a later session requires a newly prepared adapter/client.
- The worker is serialized per client. The runtime's existing fixed worker count and bounded submission window continue to bound concurrent source operations.

## Error and data handling

Worker exceptions are not serialized to the parent. The IPC protocol returns only a small status tuple and, on success, the bounded response bytes. The worker receives the URL and request body over its private pipe, not as process command-line arguments. The implementation does not emit request bodies, endpoint values, or raw exception text to logs or metrics. Endpoint validation continues to reject embedded user information, query strings, and fragments.

## Scope and limitations

- The absolute deadline applies to source collection calls. Worker startup is bounded by a separate startup timeout and occurs before collection_started.
- Journal append/fsync, audit, replay, and final report construction remain outside the source-collection deadline, as already disclosed by the runtime.
- Process termination is the enforcement boundary for blocked resolver, connect, TLS, header, and body operations. OS scheduling and process teardown can add bounded cleanup latency; the API does not claim nanosecond-exact wall-clock termination.
- The implementation relies on the platform's multiprocessing spawn support and standard-library TLS stack. Linux and Windows CI coverage is required before claiming cross-platform verification.
- This is transport deadline enforcement, not provider authenticity, chain consensus, or live endpoint verification.
- The DNS-only resolver from PR #20 remains available as a standalone component but is not required inside the supervised HTTP worker.

## Consequences

EVM and Solana adapters may advertise deadline_enforced = True only because their coordinator-facing *_until methods now route every JSON-RPC call through this worker and runtime preparation starts the worker before collection begins. Direct non-deadline calls also receive a finite policy timeout and use the same supervised path.
