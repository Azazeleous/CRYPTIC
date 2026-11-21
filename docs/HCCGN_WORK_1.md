# HCCGN-WORK/1 — Canonical Network Work Profile

Status: newly defined normative profile for CRYPTIC/GCF integration.
Profile ID: HCCGN-WORK/1. Proof envelope: HCCGN-PROOF/1.
Digest: single SHA-256 with domain separation. All integers are unsigned big-endian.
This is a new protocol decision, not a recovered historical wire format.

## Purpose

HCCGN-WORK/1 defines a reproducible proof-of-work header and verifier for GCF proposals. It does not replace proposer signatures, validator voting, GOD authorization, GAIA-JUSTICE evidence, or finality. Work validity establishes only that a candidate satisfies the active network target.

Retained computation constants: primary modulus 97,152 with totient 28,160; compact modulus 1,518 with totient 440. Both strides are committed in the header and must be coprime to their respective moduli. This makes each modular traversal a permutation with a unique inverse; it does not invert SHA-256.

## Exact binary header

The header is exactly 184 bytes with no optional fields or padding.

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII HCCGNW01 |
| 8 | 2 | version | u16; exactly 1 |
| 10 | 32 | network_id_hash | SHA-256(UTF-8 network_id) |
| 42 | 8 | height | u64; >= 1 |
| 50 | 8 | sequence | u64; >= 1; binds to GCF proposal epoch |
| 58 | 8 | timestamp | u64 Unix seconds |
| 66 | 32 | parent_hash | raw 32-byte digest |
| 98 | 32 | payload_hash | raw 32-byte digest |
| 130 | 4 | param_a / primary_modulus | u32; exactly 97,152 |
| 134 | 4 | param_b / compact_modulus | u32; exactly 1,518 |
| 138 | 4 | param_c / primary_stride | u32; 1..97,151 and gcd(stride,97,152)=1 |
| 142 | 2 | flags / compact_stride | u16; 1..1,517 and gcd(stride,1,518)=1; this field is a stride, not a bitmask |
| 144 | 8 | nonce | u64 |
| 152 | 32 | target | unsigned 256-bit big-endian threshold |

Canonical struct format: >8sH32sQQQ32s32sIIIHQ32s.
The target field is not self-authorizing. The verifier must compare it byte-for-byte with the active target resolved from authenticated network policy. A proposer cannot choose its own easier target. The nonce begins at header offset 144.

## Digest and acceptance

Let H be the exact 184 header bytes.

WORK_DOMAIN = ASCII(HCCGN-WORK/1) || 0x00
work_digest = SHA256(WORK_DOMAIN || H)
work_integer = OS2IP_BE(work_digest)
target_integer = OS2IP_BE(header.target)
valid_work = work_integer <= target_integer

The comparison is inclusive and big-endian. Exactly one SHA-256 invocation is used, not SHA-256d. No display-endian reversal is permitted.

## Midstate nonce mining

The full SHA-256 input is 13-byte WORK_DOMAIN followed by the 184-byte header. The nonce begins at absolute stream offset 157 (13 + 144). Therefore the first 128 bytes are invariant across nonce attempts and can be hashed once. For each candidate, copy the SHA-256 state after those two complete blocks, overwrite the nonce at tail offset 29, update with the remaining 69 bytes, and finalize. The implementation in `src/consensus/hccgn_work.py` uses this bounded midstate loop and refuses nonce-range wraparound. The optimization must be checked against full SHA-256 for multiple nonce values; it does not change the digest or protocol.

## Residue traversal projection

Let x = OS2IP_BE(work_digest[0:8]).

- primary_quotient, primary_residue = divmod(x, 97152)
- compact_quotient, compact_residue = divmod(x, 1518)
- primary_index = ((nonce mod 97152) * primary_stride) mod 97152
- compact_index = ((nonce mod 1518) * compact_stride) mod 1518
- primary_inverse = primary_stride^(-1) mod 97152
- compact_inverse = compact_stride^(-1) mod 1518

The verifier checks both gcd conditions and inverse identities. Quotient/residue and traversal indices are deterministic receipt fields, not substitutes for the SHA-256 target predicate.

## Proof envelope and commitment

Exact envelope bytes:

ASCII(HCCGN-PROOF/1) || 0x00 || u16_be(header_length=184) || header[184] || work_digest[32]

The GCF proposal proof_hash is SHA256(exact_proof_envelope_bytes). The provider resolves the exact envelope by this digest and recomputes both work digest and envelope commitment.

## GCF proposal binding

The provider requires header network hash = SHA-256(UTF-8 proposal.network_id); header height = proposal.height; header sequence = proposal.epoch; parent_hash and payload_hash equal the proposal fields; timestamp equals proposal.issued_at; target equals the independently resolved active target; proof envelope hash equals proposal.proof_hash; and work digest satisfies the inclusive target comparison. GCF expiry and clock-skew checks remain independent.

## Fail-closed behavior

Reject wrong length, magic, version, malformed hashes, wrong modulus, non-coprime stride, inverse mismatch, wrong network/epoch/height/parent/payload/timestamp, target mismatch, digest mismatch, proof commitment mismatch, and target miss. Unknown profile IDs are never silently downgraded.

## Known-answer vector

Inputs: network ID gaia-testnet; height 1; sequence 1 (GCF epoch 1); timestamp 1700000000; parent hash 11 repeated 32 bytes; payload hash 22 repeated 32 bytes; strides 5 and 7; nonce 42; maximum 256-bit target. This is a serialization/digest vector, not a production difficulty setting.

Header length: 184 bytes.
Header hex:

484343474e573031000116ae5342937422ee10b0e9640983086ee692b6fa78482506a5a1b807ce14ee5000000000000000010000000000000001000000006553f1001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222200017b80000005ee000000050007000000000000002affffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

Work digest: c823ee2a5d77e8576b1b4213bcdcca983b31c8b1c55743059f240957d9467f71
Proof envelope SHA-256: b48d21de1459758e3ffa8ed5a6e8a4488491787a4cd285bd93def24d3b36bb57

With target 00 followed by 31 bytes of ff committed into a second header, the resulting work digest is 0654fc8c10a9a9a5dbb4ad82c6621608f5b596fb053cc6a467a9b3a6fdb70560 and the proof envelope SHA-256 is 6aa84b5c7f01360a8f133d4a2144e7e333845905102eec7c0ba5ba1a62db3b2e. That digest exceeds the committed low target and must fail. Changing the target changes the header and therefore changes the digest.

## Deployment and governance

The branch now includes `src/consensus/hccgn_registry.py`:
- `HCCGNProofStore` stores proof envelopes in SQLite under SHA-256 content addresses, enforces a 1 MiB maximum, verifies content on retrieval, and uses WAL plus synchronous FULL commits.
- `HCCGNActiveTargetPolicy` verifies Ed25519-signed `HCCGN-TARGET-POLICY/1` snapshots against an operator-pinned public key and signer ID. Snapshots bind network, profile, monotonically increasing sequence, target, issue/expiry times, and activation height/epoch.
- The resolver selects only a policy whose activation boundary covers the proposal and whose validity window is current. Missing, expired, malformed, wrong-signer, or rolled-back policy returns no target.
- The provider can be connected directly as `HCCGNWorkProofProvider(proof_store.get, target_policy.resolve)`.

The policy database enforces monotonic sequence within its retained database. Restoring an older database snapshot can defeat database-local rollback detection; production deployments must anchor the latest policy sequence in the independently protected GOD/APEX root-of-trust or another monotonic durable checkpoint. The actual GOD public key is not embedded in CRYPTIC and must be provisioned out of band. No live policy has been activated by this code change.

An independent Go implementation in `conformance/go` parses the 184-byte header and verifies the same proof envelope using only Go's standard library. CI now runs its known-answer vector alongside Python tests. `scripts/benchmark_hccgn_work.py` measures the actual 128-byte-midstate hashing kernel, reports attempts/second and checks the final result against full SHA-256. It explicitly does not claim target-search throughput or production mining capacity. Cross-language vector agreement is necessary but does not by itself prove a deployed GOD authorization or live network activation.

The Architect / Nexus / Cryptic News LLC / Project: The Nexus Generation: GaiaSSoul / SERIES: The Nexus of Gaia / ID: 137451921129154222|040592|433855274