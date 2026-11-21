# ADR-0022: Canonical transport translation and reversible representations

- Status: proposed for implementation after v2.3 transport review
- Date: 2026-11-21
- Scope: request/response representation, encoding, decoding, and safe transformation reuse
- Security boundary: read-only JSON-RPC only

## Context

The supervised HTTP worker establishes the blocking-I/O boundary. It does not by itself minimize repeated representation work between callers, JSON-RPC, UTF-8 bytes, the worker IPC envelope, and the decoded observation model.

The mathematical identities supplied for vector calculus and differential forms suggest useful invariants, but they must be applied only where their algebraic preconditions hold. In particular, d^2=0 is an identity for the exterior derivative, not a universal rule that arbitrary transport transformations may be composed away.

## Decision

Introduce a canonical, typed transport representation (CTR) between application-level requests and transport-specific encoders.

```text
typed request
  -> validate + normalize
  -> canonical transport representation (CTR)
  -> encode once to bounded UTF-8 bytes
  -> supervised HTTP worker
  -> bounded response bytes
  -> decode + validate
  -> typed response / observation
```

A CTR envelope contains:

- schema and version identifiers;
- protocol and operation identifiers;
- typed parameters with explicit distinction between absent, null, zero, false, and empty values;
- canonicalization profile;
- correlation identifier and request identifier;
- declared byte length and encoding;
- transformation-chain identifiers and reversibility declarations.

Secrets, authorization material, and credentials are excluded from logs, metrics, cache keys, and diagnostic receipts.

## Algebraic optimization rules

Represent each transformation as a typed function T_i: X_i -> X_(i+1). A transform may be removed only when its identity behavior is proven for the actual input type and profile.

1. **Identity elimination:** if T_i = I under the active schema/profile, omit the transform and preserve the input bytes.
2. **Inverse cancellation:** T^-1(T(x)) = x may be used only for a transform with a tested inverse and matching version/parameters. Verify equality at the defined canonical byte boundary.
3. **Zero/empty handling:** zero, null, absent, false, and empty are distinct wire values. Do not collapse them. A zero contribution may be omitted only when the protocol schema defines it as an algebraic identity and omission is semantically equivalent.
4. **Composition:** combine adjacent transforms only when their domains/codomains and ordering are compatible and a reference implementation proves equivalence.
5. **Non-commuting transforms:** preserve order whenever T_a composed with T_b differs from T_b composed with T_a. Gauge-theory commutators are an analogy for this ordering constraint, not an implementation of gauge fields in HTTP.
6. **Differential invariant:** use d^2=0 only in a separately typed differential-form validation module. It is not a generic transport cancellation rule.

## Safe reuse and caching

- Cache only canonical, validated, explicitly cacheable read results.
- Cache identity includes endpoint/network identity, RPC method, canonical parameters, schema version, and relevant consistency/finality context.
- Never cache moving-head methods such as eth_blockNumber, eth_getBlockByNumber("latest"), getSlot, or getBlockHeight without an explicit bounded freshness policy; default is no cache.
- JSON-RPC request IDs are transport correlation fields, not semantic cache identity. Regenerate IDs on cache hits.
- Do not reuse results across different endpoint identities merely because payload bytes match.
- Cache entries are advisory; every cache hit reports age and provenance and remains subject to response validation.

## Encoding and decoding invariants

- Canonical JSON is encoded once per outbound request.
- UTF-8 byte length is checked before IPC.
- The existing request and response byte limits remain authoritative.
- The worker receives only bounded, validated request data.
- Decode rejects invalid UTF-8, malformed JSON, wrong schema/version, mismatched request IDs, and invalid typed fields.
- A reversible transformation receipt records input/output digests, transform identifiers, parameters (non-secret only), and verification result.
- SHA-256 digests identify byte strings; they do not make a lossy transform reversible and do not authenticate a provider.

## Performance model and measurement

Measure, rather than assume, improvement. Record bounded counters/timers for:

- normalization time;
- canonical serialization time and bytes;
- encoding/decoding time and bytes;
- transform count and identity-transform eliminations;
- verified inverse round trips;
- cache hits/misses/age where caching is enabled;
- total request latency and worker wait time.

Compare the reference path and optimized path over the same deterministic corpus. Require byte-for-byte canonical output equivalence and identical decoded semantic values. Report p50/p95 latency, throughput, allocation/peak-memory measurements where available, and error rates. Do not claim acceleration unless the benchmark demonstrates it.

## Acceptance tests

1. Absent, null, zero, false, empty string, empty array, and empty object remain distinguishable.
2. Canonical encoding is deterministic across repeated runs.
3. Decode(Encode(x)) equals the validated canonical representation of x.
4. Every declared reversible transform passes forward/reverse property tests and boundary cases.
5. Identity elimination is byte-equivalent to the reference pipeline.
6. Transform composition preserves order and output.
7. Cache keys cannot cross endpoint identity, schema version, or consistency context.
8. Moving-head methods are not cached by default.
9. Oversized input is rejected before worker IPC.
10. The read-only RPC allowlists remain unchanged.

## Consequences

This layer can reduce redundant parsing, serialization, and repeated deterministic transforms. It does not reduce network round trips unless a separately justified batching protocol is introduced. It does not invert cryptographic hashes, prove consensus, or grant write capability.

The supervised HTTP worker remains the execution boundary. Canonical translation is an optimization above that boundary and must not weaken its deadline, size, TLS, redirect, or worker-poisoning guarantees.
