# CRYPTIC Post-Quantum Cryptography

## Adopted algorithm suite

CRYPTIC adopts the following standardized algorithms as its initial PQ integration target:

| Purpose | Algorithm | Standard |
|---|---|---|
| Key encapsulation / shared-secret establishment | ML-KEM-768 | NIST FIPS 203 |
| Primary digital signatures | ML-DSA-65 | NIST FIPS 204 |
| Optional independent signature family | SLH-DSA | NIST FIPS 205 |
| Key derivation | HKDF-SHA-256 | RFC 5869 |
| Authenticated encryption | ChaCha20-Poly1305 | RFC 8439 |
| Content digest | BLAKE2b-256 | RFC 7693 |

ML-KEM is a key-establishment mechanism, not a signature or peer-authentication mechanism. Authenticate the peer's ML-KEM public-key binding and session transcript using enrolled ML-DSA identities or another explicitly trusted authentication mechanism.

## Integration status

The algorithms are selected at the architecture level. This document does not claim that implementations, key storage, interoperability, or production deployment are complete. Runtime integration must use vetted, maintained cryptographic libraries with current NIST errata, known-answer tests, dependency review, and license review. CRYPTIC must not implement ML-KEM, ML-DSA, or SLH-DSA from scratch.

## Four-lane session model

Each lane has its own identity key pair and authorization record. A session establishes a shared secret through ML-KEM and derives purpose-separated keys with HKDF using transcript-bound context. Lane identifiers, protocol version, job ID, peer identities, and algorithm suite identifiers are included in the derivation context.

Do not share one lane's private signing key with other lanes. Do not use a single derived key for unrelated purposes. Use a distinct key for each lane, direction, and protocol purpose.

## Message protection

ChaCha20-Poly1305 protects confidential lane messages. The 96-bit nonce must never repeat under the same key. Sequence numbers and session identifiers support replay detection but do not replace nonce uniqueness. The complete canonical envelope, including protocol and lane metadata, is authenticated as associated data where appropriate.

ML-DSA signs durable checkpoints, job manifests, and batch commitments. Do not sign every nonce candidate: batch-level signatures avoid making signature generation a mining bottleneck. SLH-DSA is an optional alternative signature profile, not a lattice algorithm.

## Key lifecycle

- Generate private keys inside an approved cryptographic provider or protected key store.
- Register public keys with identity, purpose, algorithm, validity, and revocation metadata.
- Authenticate ML-KEM public-key distribution; KEM alone does not authenticate a peer.
- Rotate keys with overlap and explicit activation/revocation timestamps.
- Preserve verification metadata for historical records without retaining unnecessary private keys.
- Never log private keys, shared secrets, seed material, or derived traffic keys.
- Reject unknown algorithms, downgraded suites, invalid signatures, expired identities, and revoked keys.
- Keep protocol versioning and algorithm negotiation downgrade-resistant.

## Security boundary

PQ cryptography protects identities, session establishment, communications, and signed records. It does not accelerate proof-of-work, change the consensus hash, make a custom barrel-roll transform cryptographically secure, or prove that mining work was economically useful.
