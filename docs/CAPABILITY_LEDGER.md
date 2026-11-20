# Capability Ledger

| Capability | Status | Evidence required |
|---|---|---|
| Repository architecture | scaffolded | reviewed architecture and ADRs |
| Read-only source registry and adapter interface | implemented (E3) | PR #11; CI run 44789964655 passed unit tests and bounded benchmark; provider integrations remain unverified |
| Market-data source adapters | proposed | live adapter tests with provenance |
| Bounded JSON-RPC transport | implemented (E3) | HTTPS/loopback policy, response bounds, request IDs, read-only allowlist, retries and per-client request spacing; PR #12 CI verified |
| Raw observation journal | implemented (E3) | PR #13; CI run 44791258725 passed unit tests and bounded benchmark; canonical JSONL, SHA-256 chain, fsync, OS file locking, tamper detection; no privileged/WORM claim |
| EVM JSON-RPC transport + chain identity | implemented (E3) | PR #12; CI run 44790661161 passed protocol/adapter tests and bounded benchmark; live provider verification remains unclaimed |
| Solana JSON-RPC transport + cluster identity | implemented (E3) | PR #12; CI run 44790661161 passed protocol/adapter tests and bounded benchmark; live provider verification and subscriptions remain open |
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
