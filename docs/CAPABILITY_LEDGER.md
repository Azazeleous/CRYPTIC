# Capability Ledger

| Capability | Status | Evidence required |
|---|---|---|
| Repository architecture | scaffolded | reviewed architecture and ADRs |
| Read-only source registry and adapter interface | implemented (E3) | PR #11; CI run 44789964655 passed unit tests and bounded benchmark; provider integrations remain unverified |
| Market-data source adapters | proposed | live adapter tests with provenance |
| Bounded JSON-RPC transport | implemented (E3) | HTTPS/loopback policy, response bounds, request IDs, read-only allowlist, retries and per-client request spacing; PR #12 CI verified |
| Raw observation journal | implemented (E3) | PR #13; CI run 44791258725 passed unit tests and bounded benchmark; canonical JSONL, SHA-256 chain, fsync, OS file locking, tamper detection; no privileged/WORM claim |
| Chain normalization and discrepancy reports | implemented (E3) | PR #14; CI run 44791838680 passed normalization, identity, discrepancy, and bounded benchmark tests; no consensus-validity claim |
| Deterministic journal replay and data-quality reporting | implemented (E3) | PR #15; CI run 44792211628 passed replay, tamper, regression, duplicate, discrepancy, and bounded benchmark tests; no network calls during replay |
| Bounded ingestion coordinator | implemented (E3) | PRs #16–#21; PR #21 CI run 44826272286 passed unit tests and bounded benchmark on head a05e4bf624b64c9c2cb46af14dd67c39d0087f8f. Fixed worker/submission-window bounds, page/observation budgets, deadline accounting, shared-deadline JSON-RPC propagation, and isolated DNS foundation are retained. v2.3 adds a prestarted spawn-based whole-request HTTP worker, parent-side absolute-deadline event wait, fixed-capacity shared-memory response, worker termination/poisoning, redirect denial, and bounded request/response reads. Runtime prepares selected adapters before collection begins and closes transports on orderly shutdown. Tests cover normal response, redirect denial, response cap, slow-trickle termination, JSON-RPC integration, and preparation-before-deadline. Journal fsync/audit/replay remain outside the source-collection deadline; Windows spawn CI and live provider verification remain unclaimed. |
| EVM JSON-RPC transport + chain identity | implemented (E3) | PR #12, #14, and #21; whole-request process boundary passed PR #21 CI run 44826272286. Identity uses chain ID plus genesis hash; live provider verification remains unclaimed. |
| Solana JSON-RPC transport + cluster identity | implemented (E3) | PR #12, #14, and #21; whole-request process boundary passed PR #21 CI run 44826272286. Identity uses genesis hash; live provider verification and subscriptions remain open. |
| Complete asset coverage | unverified | provider-by-provider coverage and limits |
| Canonical chain identity | implemented (E3) | PR #14; EVM chain ID + genesis hash and Solana genesis hash; cross-source comparisons require matching network identity |
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
