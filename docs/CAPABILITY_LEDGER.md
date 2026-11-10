# Capability Ledger

| Capability | Status | Evidence required |
|---|---|---|
| Repository architecture | scaffolded | reviewed architecture and ADRs |
| Market-data source adapters | proposed | live adapter tests with provenance |
| EVM RPC | proposed | chain ID, block, log, reconnect tests |
| Solana RPC | proposed | genesis identity and subscription tests |
| Complete asset coverage | unverified | provider-by-provider coverage and limits |
| Canonical asset identity | proposed | collision and alias test suite |
| Model routing | proposed | provider contract and evaluation |
| Local model inference | proposed | reproducible benchmark on target hardware |
| Extension absorption | proposed | sandbox, manifest, conformance, permission tests |
| GF(256) | proposed | field axioms and known-answer tests |
| Reed–Solomon | proposed | encode/decode vectors and error-bound tests |
| Berlekamp–Welch | proposed | polynomial reconstruction tests |
| QC-LDPC | proposed | parity-check, syndrome, decoder convergence tests |
| Three-lane correction | proposed | fault injection and independent re-verification |
| Chunked sparse storage | proposed | layout benchmark, crash recovery, integrity tests |
| Virtual computer/SOS | proposed | isolation and escape-resistance tests |
| Device assistant | proposed | enrollment, scope, revoke, audit tests |
| Local seed and Merkle ledger CLI | implemented (E2) | seven local unit tests pass; repository commit and runtime integration still require CI/integration evidence |
| Four-lane SHA-256 mining reference | implemented (reference) | eight local unit tests pass; CI, chain-specific header adapter, pool adapter, and production benchmarks remain |
| Reversible barrel-roll framing | implemented (reference) | bit/byte/lane inverse and round-trip tests pass locally; framing does not modify consensus hashes |
| 97,152 affine candidate scheduler | implemented (reference) | full-period permutation and disjoint four-lane coverage tests pass locally |
| ML-KEM-768 suite selection | adopted design | vetted provider, official vectors, authenticated key binding, and interoperability tests |
| ML-DSA-65 suite selection | adopted design | vetted provider, official vectors, key lifecycle, and signature interoperability tests |
| SLH-DSA optional profile | adopted design | provider selection and optional-profile interoperability tests |
| PQ key lifecycle/runtime | proposed | protected key store, rotation, revocation, replay, and recovery tests |
| BLE/home automation | proposed | device-specific authorization and safety tests |

Update this ledger only with reproducible evidence. Never mark a feature complete because its directory, interface, or design document exists. Local test results do not substitute for repository CI or production evidence.
