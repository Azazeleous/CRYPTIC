# CRYPTIC Provenance Trust Lifecycle v1.2

## Scope

This layer adds immutable, versioned trust-policy snapshots, key rotation,
effective-time revocation, historical verification, and collection-level
multi-issuer quorum checks. It does not modify the v1.1 attestation envelope
or existing receipt, trophy, index, and federation schemas.

## Trust snapshot

Schema: `cryptic.provenance-trust-snapshot.v1`

A snapshot contains:

- monotonically increasing integer version;
- signed-policy metadata timestamp `created_at` (not a trusted timestamp);
- previous snapshot digest for versions after v1;
- issuer key entries sorted by issuer ID and key fingerprint;
- SHA-256 digest over the canonical snapshot body.

Each issuer key entry binds issuer ID, raw Ed25519 public key, public-key
fingerprint, `valid_from`, and optional `revoked_at`. Duplicate public-key
fingerprints are rejected. Key validity uses the half-open interval
`[valid_from, revoked_at)`; a null revocation means no scheduled end.

Snapshots are immutable values. Rotation and revocation create a new version
and preserve the previous snapshot unchanged. The new snapshot references
the prior snapshot digest and increments its version by one.

`verify_trust_snapshot()` always checks the supplied snapshot's canonical
digest. For versions after v1, a standalone check explicitly reports that
the predecessor chain is unchecked. Supplying the immediate predecessor
checks that direct link and reports `chain_link_verified`.
`verify_trust_snapshot_chain()` accepts the ordered history beginning at v1
and checks every link sequentially; use this when claiming that the complete
supplied history is internally consistent.

## Key rotation and revocation

`rotate_trust_key()` atomically:
1. locates exactly one active key for the issuer;
2. records the old key's `revoked_at` effective timestamp;
3. adds the replacement public key with `valid_from` at that same timestamp;
4. creates the next linked snapshot.

`revoke_trust_key()` records an effective revocation without adding a
replacement key. For snapshots after v1, both operations require the
complete predecessor history and refuse to advance an unverified chain.
Both operations reject unknown or ambiguous keys, duplicate new public keys,
invalid timestamps, and invalid source snapshots.

Revocation timestamps are policy data. They are not proof of when a real-world
event occurred. Clock accuracy and the authority allowed to publish a trust
snapshot remain governance responsibilities.

## Verification modes

- `verify_attestation_historical()` checks whether the signing key was valid
  at the attestation's signed `issued_at` timestamp. A signature made before
  a later revocation can remain historically valid.
- `verify_attestation_current()` checks the attestation and requires the key
  to be unrevoked as of the snapshot's `created_at` policy state. A future
  scheduled revocation does not take effect early.

Both modes verify the Ed25519 signature and key fingerprint through the
existing v1.1 verifier. For snapshots after v1, callers must supply the full
ordered predecessor history; verification fails closed if it is missing or
invalid. The current mode means active under the supplied snapshot's
`created_at` policy state; it is not a live wall-clock lookup.
Neither mode treats `issued_at` or `created_at` as a trusted clock. The
caller must select the correct snapshot and verification mode for the audit
question.

## Quorum verification

`verify_attestation_quorum()` accepts a collection of individual
attestations and a positive threshold. It requires:

- every counted attestation to verify under the supplied trust snapshot;
- distinct issuer IDs and distinct public-key fingerprints;
- exact agreement on subject schema, subject ID, digest algorithm, and digest;
- consistent signed purpose across counted attestations.

Repeated attestations from one issuer do not increase the count. Invalid
signatures, unknown/revoked keys, duplicate issuers, mismatched subjects, and
mismatched purposes are reported as rejected entries.

This is a collection-level quorum rule, not an aggregate signature, not a
threshold-signature protocol, and not a distributed consensus algorithm.
The threshold is a local policy parameter. It does not make the signers
independent or establish the truth of their shared statement.

## Integrity versus authenticity

The snapshot digest and previous-digest chain detect accidental changes and
broken history. They do **not** authenticate who published a snapshot.
An attacker able to replace an entire snapshot chain can recompute its hashes.

For authenticity, operators must anchor snapshot digests through an
independent trusted channel or use a separately governed root-signing
mechanism. Do not treat a self-consistent hash chain as a trusted root.

The same distinction applies to attestations: Ed25519 proves that the
corresponding private key signed the payload; the trust snapshot expresses
which issuer/key bindings the verifier accepts. Neither proves the underlying
federation is correct. Run the federation source-rebuild audit separately.

## Compatibility and boundaries

- Existing v1.1 attestations remain valid without changing their schema.
- Existing trust-store verification remains available for simple active-key
  checks.
- Snapshot lifecycle support is additive and optional.
- No private key material is stored in snapshots or repository files.
- No online revocation service, timestamp authority, trust-store publisher,
  automatic key custody, or network consensus is implemented.
- Network acceptance, valuation, transferability, and payments remain
  outside this subsystem.

## Governing invariants

**Boundary** — Nothing executes beyond its time.

**Capacity** — Nothing claims capacity without measurement.

**Correctness** — Nothing claims correctness without verification.
