# CRYPTIC Root of Trust v1.3

## Purpose

This layer authenticates governance policy statements with an independently
pinned Ed25519 root. It closes the v1.2 gap where a complete, internally
consistent snapshot hash chain could still be replaced by an attacker who
recomputed every digest.

The root fingerprint is the trust anchor. It must be obtained and pinned
through a channel independent of the repository or snapshot being verified.
A fingerprint copied from the same untrusted archive as the manifest is not
an independent trust anchor.

## Public root manifest

Schema: cryptic.governance-root.v1

The canonical manifest contains a monotonically increasing epoch, sorted
unique Ed25519 root public keys, a root-signature threshold, a separately
designated recovery-key set and recovery threshold, the previous root
fingerprint for epochs after 1, and a domain-separated SHA-256 root
fingerprint. No private key material is serialized.

## Signed policy envelope

Schema: cryptic.signed-policy-snapshot.v1

The envelope binds the canonical SHA-256 digest of a valid v1.2 trust
snapshot to the pinned root fingerprint, root epoch, monotonically increasing
policy sequence, optional predecessor policy digest, and Ed25519 signatures.

Verification requires a valid root manifest, exact match with the caller's
independent root pin, valid trust snapshot and complete ordered history for
snapshots after version 1, matching root epoch and content digest, a sequence
at or above the caller's anti-rollback floor, and the configured number of
distinct root-key signatures.

For sequence numbers after 1, the envelope must contain a valid predecessor
digest. When expected_previous_policy_digest is supplied, the predecessor
must match exactly. The caller must persist its highest accepted sequence
and last accepted digest in storage protected against rollback. This library
does not provide durable monotonic storage; resetting that state resets the
caller's anti-rollback protection.

## Root rotation and recovery

Schema: cryptic.root-rotation.v1

A root transition requires the new manifest epoch to increment exactly once,
the new manifest to name the old root fingerprint as predecessor,
authorization by the old root threshold (or the separately configured
recovery threshold), and proof of possession from the new root's configured
threshold of keys.

The verifier checks old authorization and new-key possession signatures
over the same domain-separated transition payload. After successful
verification, the operator must independently pin the returned new root
fingerprint before trusting policy statements under the new root.

Recovery authorization is available only when recovery keys and a nonzero
recovery threshold were explicitly configured in the previous root
manifest. Loss of both ordinary and recovery quorum means there is no
cryptographic in-band recovery path; establish a new trust anchor through a
separately authenticated out-of-band governance process.

## Cryptographic and operational boundaries

- Ed25519 signatures use distinct domain-separation strings for policy and
  root-transition statements.
- Signer fingerprints are derived from raw 32-byte public keys.
- Duplicate signatures from one key do not increase quorum.
- Canonical JSON serialization is inherited from the attestation subsystem.
- A valid signature proves that the corresponding private key signed the
  exact payload; it does not prove the signed policy is wise or true.
- The root fingerprint is meaningful only when independently pinned.
- The sequence floor works only when the caller persists it outside the
  untrusted archive and prevents rollback of that state.
- Signed timestamps are not trusted timestamps.
- Private-key generation, secure storage, offline custody, backups, operator
  identity proofing, and hardware security modules are outside this module.
  Keep root and recovery private keys offline and never commit them.
- Root rotation and recovery are governance operations, not network
  consensus. This layer adds no external network acceptance, payments,
  valuation, transferability, or token issuance.

## Example integration

\`\`\`python
from src.mining.root_of_trust import (
    verify_signed_policy_snapshot,
    verify_root_rotation,
)

policy_result = verify_signed_policy_snapshot(
    envelope,
    trust_snapshot,
    root_manifest,
    pinned_root_fingerprint=independently_pinned_fingerprint,
    minimum_sequence=last_accepted_sequence + 1,
    expected_previous_policy_digest=last_accepted_policy_digest,
    snapshot_history=ordered_snapshot_history,
)

rotation_result = verify_root_rotation(
    transition,
    old_root_manifest,
    pinned_old_root_fingerprint=independently_pinned_fingerprint,
)
\`\`\`

The example leaves persistence and fingerprint distribution to the calling
governance system. A verifier must update its trusted sequence, digest, and
root pin only after successful verification and its own durable commit.

## Governing invariants

**Boundary** — Nothing executes beyond its time.

**Capacity** — Nothing claims capacity without measurement.

**Correctness** — Nothing claims correctness without verification.
