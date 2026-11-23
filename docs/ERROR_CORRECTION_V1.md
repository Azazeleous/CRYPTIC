# CRYPTIC Error-Correction Foundation v1

## Scope

This implementation adds a reproducible, testable correction stack:

1. GF(256) arithmetic over the primitive polynomial 0x11D.
2. Reed-Solomon evaluation codes with bounded unknown-symbol correction.
3. Berlekamp-Welch polynomial recovery over GF(256).
4. QC-LDPC parity checks generated from a circulant-shift base matrix.
5. Normalized min-sum decoding and independent syndrome/re-encoding checks.
6. A layered QC-LDPC then Reed-Solomon pipeline with a verification receipt.
7. Immutable content-addressed chunks with canonical manifests, atomic writes, and read-time integrity verification.
8. Three-lane correction consensus: layered QC-LDPC/RS, direct production RS, and a separately implemented bitwise-GF(256) reference RS decoder.

The QC-LDPC construction is quasi-cyclic: each nonnegative base-matrix entry denotes a circulant shift, and -1 denotes an all-zero block. The final parity blocks are required to form an identity matrix of zero-shift circulants. This gives a systematic encoder without constructing or inverting a dense random matrix. This is the selected QC-LDPC approach; it is not a random sparse LDPC matrix.

## Wire and algorithm boundaries

- GF(256) symbols are integers 0 through 255.
- Reed-Solomon uses a non-systematic evaluation profile. The k message bytes are the ascending polynomial coefficients; the n symbols are evaluations at alpha**0 through alpha**(n-1).
- The unknown-error correction bound is floor((n-k)/2). Erasure decoding is not implemented or claimed.
- QC-LDPC bit ordering is message bits followed by parity bits, most-significant bit first when bytes are mapped into bits.
- LLR values use positive values as evidence for bit zero and negative values as evidence for bit one.
- The min-sum decoder reports convergence only when the hard decision has zero syndrome.
- The layered stack fails closed if QC-LDPC does not converge or if the RS result fails independent re-encoding.
- The three-lane coordinator requires two matching message/codeword results. A single lane cannot authorize output.
- Lane 1 uses the layered QC-LDPC -> production RS path; lane 2 decodes the systematic information bits directly with the production RS decoder; lane 3 uses an independent bitwise-GF(256) Berlekamp-Welch implementation with a separate Gaussian solver.
- Every accepted candidate must pass both production and reference RS re-encoding and QC-LDPC re-encoding/syndrome verification. No two-lane agreement fails closed.
- The reference decoder is an independently written implementation of the same bounded evaluation-code profile; it is not a different code family or a formal proof.

## Modules

- src/error_correction/gf256.py
- src/error_correction/berlekamp_welch.py
- src/error_correction/reed_solomon.py
- src/error_correction/qc_ldpc.py
- src/error_correction/pipeline.py
- src/error_correction/storage.py
- src/error_correction/reference_rs.py
- src/error_correction/three_lane.py

## Verification

tests/test_error_correction.py covers field inverses and primitive-element cycling, polynomial evaluation, two-error Berlekamp-Welch recovery, Reed-Solomon correction at the configured bound, QC-LDPC systematic encoding, single-bit syndrome correction, layered round-trip, and fail-closed decoder configuration. tests/test_chunk_store.py covers canonical manifests, deduplication, empty content, chunk tampering, manifest tampering, and invalid chunk sizes. tests/test_three_lane_correction.py covers an independent reference-decoder error sweep, three-way agreement, two-lane recovery after one lane fails, no-majority rejection, decoder-budget validation, and non-finite LLR rejection.

The chunk store uses SHA-256 content addressing, immutable manifest IDs, same-directory atomic replacement, file fsync, and best-effort directory fsync. Reads are side-effect free and verify every chunk digest, declared size, total size, and whole-content digest. Platform-specific power-loss durability remains unverified.

CI evidence on source commit db726ee691c292df4e84777a6ed9f16c604e2206:

- CRYPTIC CI run 45214995986 — 393 tests passed.
- Mining-engine run 45214995960 — 393 tests passed; independent Go HCCGN conformance and bounded HCCGN/SHA-256d benchmark steps passed.
- GAIA local trophy workflow run 45214996067 — passed.

The code is a software reference implementation. It does not claim hardware acceleration, constant-time operation, formal proof, physical power-loss durability, or production deployment. The three-lane design uses two separately written RS decoders plus the layered QC-LDPC/RS path; a third-party implementation and formal proof remain future verification work. Benchmarks and platform-specific performance claims require separate measurements.
