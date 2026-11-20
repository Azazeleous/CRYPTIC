# ADR: Isolated DNS resolver lifecycle

## Status

Proposed implementation increment for ingestion v2.2. Not yet integrated into
the JSON-RPC HTTP transport and not a deadline-enforcement claim for EVM or
Solana adapters.

## Context

The existing JSON-RPC client uses Python's standard-library URL opener.
Socket timeouts bound socket operations but do not reliably bound the
platform name-resolution call that can occur before connection establishment.
The ingestion runtime correctly rejects adapters that do not advertise
complete deadline enforcement.

## Decision

Introduce a small, supervised resolver process using the multiprocessing
`spawn` context. The process is started during adapter preparation, before
the source-collection deadline begins. Requests use a parent-side monotonic
deadline and a bounded IPC poll. If a lookup exceeds that deadline, the parent
terminates the resolver, marks the instance poisoned, and fails the current
operation. The instance is never silently restarted during that session.

The resolver returns only validated IPv4/IPv6 stream address tuples. It does
not open network connections, choose an endpoint, perform HTTP, or alter
source policy. IP literals bypass DNS.

## Consequences and limits

- Process startup is preparation work and is not covered by the collection
  deadline. Preparation must complete before the runtime starts collection.
- A timed-out resolver is discarded; the owning adapter/session must abort or
  be rebuilt outside the active collection deadline.
- The resolver alone does not pin an HTTPS connection to an address and does
  not prove TLS SNI or certificate-hostname behavior. A separate transport
  increment must connect to the resolved address while validating TLS against
  the original hostname.
- Redirects must remain disabled or be revalidated against the original
  endpoint policy. Response-size, retry, rate-gate, and shared-deadline rules
  remain in force.
- EVM and Solana adapters must continue to declare
  `deadline_enforced = False` until DNS, connect, TLS, response reads, and
  cancellation are integrated and tested as one transport boundary.
- This component is read-only infrastructure; it adds no transaction,
  signing, wallet, submission, or financial participation capability.

## Verification required before adapter enablement

1. Resolver startup and cleanup on supported spawn platforms.
2. Hanging lookup is terminated by the parent within the supplied deadline.
3. Resolved addresses are validated and deterministically de-duplicated.
4. HTTPS connects to the pinned address but preserves original-host SNI and
   certificate verification.
5. Connect and response reads consume the same absolute monotonic budget.
6. Redirect, response-size, endpoint-policy, and allowlist regressions pass.
7. The bounded runtime accepts the adapters only after all above guarantees
   are demonstrated in CI.

The resolver tests in this increment establish basic worker lifecycle,
localhost resolution, literal-IP handling, and expired-deadline behavior only.
