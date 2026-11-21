# Capability Ledger

| Capability | Status | Evidence required |
|---|---|---|
| Repository architecture | scaffolded | reviewed architecture and ADRs |
| Standalone GCF/1 finality verifier | implemented (E3) | Independent implementation in `src/consensus/independent_verifier.py`; no GCFEngine private validation calls; ADAM/APEX uses this verifier; certificate, quorum, POLC, signature and tamper tests added; CI run 44916647888 passed 234 tests (2 skipped) |
| HCCGN-WORK/1 header, verifier and midstate miner | implemented (E2; CI pending) | `docs/HCCGN_WORK_1.md`, `src/consensus/hccgn_work.py`, and `tests/test_hccgn_work.py`; supplied 184-byte layout and field semantics, SHA-256 domain separation, independently pinned target, proposal binding, proof-frame commitment, coprime stride checks, 128-byte SHA-256 midstate miner, full-hash equivalence tests and rejection vectors; proof-store and active-target resolvers remain deployment inputs |
| GCF direct-peer transport | implemented (E3; loopback TLS tested) | `src/consensus/peer_transport.py`: mutual TLS, certificate fingerprint allowlist, Ed25519 peer envelopes, validator key binding, bounded frames and persistent replay protection; loopback mutual-TLS exchange is tested; no discovery/gossip/round-change or live multi-host evidence |
| ADAM/APEX HTTP integration | implemented (E3) | Independent certificate verifier is now used for commit; POST `/v1/adam/commit`, GET `/v1/adam/head`, GET `/v1/adam/commits/{height}`; strict duplicate-key JSON parsing and bounded state payload |
| GCF/1 conformance and recovery suite | implemented (E3) | Known-answer canonical JSON/SHA-256 tests, independent verifier cross-checks, tamper/duplicate-validator, peer replay/identity, HTTP and ADAM recovery tests; 234 tests passed (2 skipped) in CI run 44916647888; cross-language and HCCGN vectors remain blocked by canonical spec |
| GCF/1 signed proposal and weighted BFT round engine | implemented (E3) | Branch CI run 44915510019 passed 215 unit tests (2 skipped) and bounded benchmark; Ed25519 proposals/votes, replay protection, strict >2/3 quorum, durable per-round vote locks, PREVOTE/PRECOMMIT and POLC certificate checks; no live validator network claim |
| GCF/1 bounded WSGI submission/status adapter | implemented (E3) | Branch CI run 44915510019; bounded JSON body, duplicate-key rejection, proposal/vote/finalize/status routes; authentication and TLS are external deployment requirements |
| ADAM SQLite commitment store + APEX finality gate | implemented (E3) | Branch CI run 44915510019; independent finality re-verification, payload/state digest match, contiguous height and parent-state hash, durable receipt and state recovery; no WORM/replication claim |
| GOD GCF network authorization adapter | partial (E2) | Calls host GOD gate `runnable()` with `gcf.consensus.propose`; inspected GOD v1 allowlist does not yet include this capability, so live network submission remains denied |
| GAIA-JUSTICE/1 commitment verifier | partial (E2) | Strict commitment shape plus injected policy/evidence verifiers; production policy/evidence providers and independent audit suite remain unconnected |
| HCCGN network proof verifier | reference profile implemented (E2; CI pending) | HCCGN-WORK/1 is normative for this branch and adopts the supplied 184-byte field layout; production activation still requires authenticated proof storage, active-target policy resolver, GOD-authorized epoch/height activation and cross-language conformance |
| Read-only source registry and adapter interface | implemented (E3) | PR #11; CI run 44789964655 passed unit tests and bounded benchmark; provider integrations remain unverified |
| Market-data source adapters | proposed | live adapter tests with provenance |
| Bounded JSON-RPC transport | implemented (E3) | HTTPS/loopback policy, response bounds, request IDs, read-only allowlist, retries and per-client request spacing; PR #12 CI verified |
| Raw observation journal | implemented (E3) | PR #13; CI run 44791258725 passed unit tests and bounded benchmark; canonical JSONL, SHA-256 chain, fsync, OS file locking, tamper detection; no privileged/WORM claim |
| Chain normalization and discrepancy reports | implemented (E3) | PR #14; CI run 44791838680 passed normalization, identity, discrepancy, and bounded benchmark tests; no consensus-validity claim |
| Deterministic journal replay and data-quality reporting | implemented (E3) | PR #15; CI run 44792211628 passed replay, tamper, regression, duplicate, discrepancy, and bounded benchmark tests; no network calls during replay |
| Bounded ingestion coordinator | partial (E3) | PR #16–#19; PR #17 CI runs 44820117950 and 44820138234 passed; PR #18 CI runs 44820874496 and 44820893547 passed 169 tests and bounded benchmark; PR #19 CI run 44821362812 passed 173 tests and bounded benchmark. Fixed worker/submission-window bounds, page/observation budgets, deadline accounting, shared-deadline JSON-RPC call API, and EVM/Solana deadline propagation are covered. Regression tests verify rate-gate wait bounds, retry-backoff budget checks, socket timeout selection, and reuse of one deadline across multi-call observations. EVM/Solana adapters deliberately remain ineligible (`deadline_enforced = False`) because standard-library DNS resolution is not isolated; runtime continues rejecting them. Journal fsync/audit/replay remain outside hard deadline. |
| EVM JSON-RPC transport + chain identity | implemented (E3) | PR #12 and #14; CI protocol/adapter tests passed; identity uses chain ID plus genesis hash; live provider verification remains unclaimed |
| Solana JSON-RPC transport + cluster identity | implemented (E3) | PR #12 and #14; CI protocol/adapter tests passed; identity uses genesis hash; live provider verification and subscriptions remain open |
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
