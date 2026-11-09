# Error Correction Architecture

The correction stack is separate from cryptographic authentication.

1. GF(256) arithmetic with a documented irreducible polynomial and known-answer tests.
2. Reed–Solomon coding for symbol-error and erasure recovery.
3. Berlekamp–Welch decoding for polynomial reconstruction under bounded errors.
4. QC-LDPC with a reproducible quasi-cyclic parity-check matrix and documented lifting parameters.
5. Three-lane pipeline: independent encode/transport/decode paths with lane-specific receipts.
6. Inline syndrome, parity, digest, and semantic consistency checks.
7. Independent re-verification after correction.

A successful decoder output is not automatically authentic. Use cryptographic hashes/MACs/signatures for integrity/authentication. Record correction counts, erasures, syndromes, decoder convergence, and failure reasons.
