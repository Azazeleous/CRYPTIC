# CRYPTIC v1.4 — Distributed Trust Verification

## Purpose

v1.4 packages the governance root, root transitions, trust-snapshot history,
and signed policy into a portable verification bundle. A receiving device
checks the bundle against a root fingerprint configured independently of the
bundle.

## Bundle structure

- Initial governance root manifest.
- Ordered root-rotation transitions.
- Ordered trust-snapshot history and current trust snapshot.
- Signed policy snapshot bound to the active root and trust snapshot.
- Canonical SHA-256 digest over the complete bundle body.

The bundle digest detects content changes relative to the digest included in
the envelope. It is not an authenticity mechanism. Authenticity is established
by the independently pinned root and the Ed25519 signatures verified under
that root and its authorized successors.

## Independent verification state

The verifier is deterministic and does not write state. It accepts optional
`previous_state` and returns `next_state` after successful verification.
The caller must persist `next_state` separately in protected local storage and
supply it on the next verification.

The state binds the highest accepted root epoch and fingerprint, policy
sequence and envelope digest, and trust-snapshot digest. When prior state is
provided, verification checks root-history continuity, snapshot-history
continuity, policy sequence advancement, and the previous policy digest.

A first-time verifier without prior state can authenticate a valid bundle and
check its internal chains, but cannot detect replay of a previously unseen
historical bundle. Loss or rollback of the external state removes that
anti-replay guarantee.

## Failure behavior

Verification fails closed for malformed bundle or state schemas, bundle digest
mismatch, root-pin mismatch, invalid root rotation, root rollback or
discontinuous root history, invalid or incomplete trust-snapshot history,
snapshot-history discontinuity, policy signature failure, policy sequence
rollback, and predecessor-digest mismatch.

## API

- `create_distributed_trust_bundle(...)` builds a deterministic bundle.
- `verify_distributed_trust_bundle(..., pinned_root_fingerprint=...)` verifies
  it against an independently configured trust anchor.
- Persist returned `next_state` externally; the verifier does not persist it.

## Scope and limitations

This is local, portable governance and provenance verification. It is not a
network consensus protocol, external network acceptance, a claim of value or
transferability, or a payment/token mechanism. Timestamps remain metadata
unless independently anchored by a trusted time source.
