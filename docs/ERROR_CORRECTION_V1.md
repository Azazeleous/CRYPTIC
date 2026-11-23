# CRYPTIC Error-Correction Foundation v1

## Scope

This implementation adds a reproducible, testable correction stack:

1. GF(256) arithmetic over the primitive polynomial 0x11D.
2. Reed-Solomon evaluation codes with bounded unknown-symbol correction.
3. Berlekamp-Welch polynomial recovery over GF(256).
4. QC-LDPC parity checks generated from a circulant-shift base matrix.
5. Normalized min-sum decoding and independent syndrome/re-encoding checks.
6. A layered QC-LDPC then Reed-Solomon pipeline with a verification receipt.

The QC-LDPC construction is quasi-cyclic: each nonnegative base-matrix entry denotes a circulant shift, and -1 denotes an all-zero block. The final parity blocks are required to form an identity matrix of zero-shift circulants. This gives a systematic encoder without constructing or inverting a dense random matrix. This is the selected QC-LDPC approach; it is not a random sparse LDPC matrix.

## Wire and algorithm boundaries

- GF(256) symbols are integers 0 through 255.
- Reed-Solomon uses a non-systematic evaluation profile. The k message bytes are the ascending polynomial coefficients; the n symbols are evaluations at alpha**0 through alpha**(n-1).
- The unknown-error correction bound is floor((n-k)/2). Erasure decoding is not implemented or claimed.
- QC-LDPC bit ordering is message bits followed by parity bits, most-significant bit first when bytes are mapped into bits.
- LLR values use positive values as evidence for bit zero and negative values as evidence for bit one.
- The min-sum decoder reports convergence only when the hard decision has zero syndrome.
- The layered stack fails closed if QC-LDPC does not converge or if the RS result fails independent re-encoding.

## Modules

- src/error_correction/gf256.py
- src/error_correction/berlekamp_welch.py
- src/error_correction/reed_solomon.py
- src/error_correction/qc_ldpc.py
- src/error_correction/pipeline.py

## Verification

tests/test_error_correction.py covers field inverses and primitive-element cycling, polynomial evaluation, two-error Berlekamp-Welch recovery, Reed-Solomon correction at the configured bound, QC-LDPC systematic encoding, single-bit min-sum correction, layered round-trip, and fail-closed nonconvergence.

The code is a software reference implementation. It does not claim hardware acceleration, constant-time operation, formal proof, storage durability, or production deployment. Benchmarks and platform-specific performance claims require separate measurements.
