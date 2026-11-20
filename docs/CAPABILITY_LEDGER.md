# Capability Ledger

| Capability | Status | Evidence required |
|---|---|---|
| Repository architecture | scaffolded | reviewed architecture and ADRs |
| Read-only source registry and adapter interface | implemented (E3) | PR #11; CI run 44789964655 passed unit tests and bounded benchmark; provider integrations remain unverified |
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
| BLE/home automation | proposed | device-specific authorization and safety tests |

Update this ledger only with reproducible evidence. Never mark a feature complete because its directory, interface, or design document exists.
