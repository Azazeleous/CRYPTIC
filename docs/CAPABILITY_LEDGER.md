# Capability Ledger

| Capability | Status | Evidence required |
|---|---|---|
| Repository architecture | scaffolded | reviewed architecture and ADRs |
| GCF/1 signed proposal and weighted BFT round engine | implemented (E3) | Branch CI run 44915510019 passed 215 unit tests (2 skipped) and bounded benchmark; Ed25519 proposals/votes, replay protection, strict >2/3 quorum, durable per-round vote locks, PREVOTE/PRECOMMIT and POLC certificate checks; no live validator network claim |
| GCF/1 bounded WSGI submission/status adapter | implemented (E3) | Branch CI run 44915510019; bounded JSON body, duplicate-key rejection, proposal/vote/finalize/status routes; authentication and TLS are external deployment requirements |
| ADAM SQLite commitment store + APEX finality gate | implemented (E3) | Branch CI run 44915510019; independent finality re-verification, payload/state digest match, contiguous height and parent-state hash, durable receipt and state recovery; no WORM/replication claim |
| GOD GCF network authorization adapter | partial (E2) | Calls host GOD gate `runnable()` with `gcf.consensus.propose`; inspected GOD v1 allowlist does not yet include this capability, so live network submission remains denied |
| GAIA-JUSTICE/1 commitment verifier | partial (E2) | Strict commitment shape plus injected policy/evidence verifiers; production policy/evidence providers and independent audit suite remain unconnected |
| HCCGN network proof verifier | reference profile implemented (E3) | HCCGN-WORK/1 header, digest, target policy, proof store, independent Go vector, and bounded miner; actual GOD root, external monotonic anchor, live network interoperability, and deployment hardware profile remain open |
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
| GF(256) | implemented (E3 reference; PR #36 CI-verified) | Primitive polynomial 0x11D; field inverse, multiplication, division, polynomial operations, and finite-field linear solving. CRYPTIC CI run 45214995986 and mining-engine run 45214995960 each passed 393 tests. |
| Reed–Solomon | implemented (E3 reference; PR #36 CI-verified) | Non-systematic GF(256) evaluation profile; corrects up to floor((n-k)/2) unknown symbol errors; erasure decoding is not claimed. PR #36 CI run 45214995986 passed 393 tests. |
| Berlekamp–Welch | implemented (E3 reference; PR #36 CI-verified) | Bounded polynomial recovery with uniqueness checks and deterministic error-position reporting. A separately written bitwise-GF(256) reference decoder is included. PR #36 CI run 45214995986 passed 393 tests. |
| QC-LDPC | implemented (E3 reference; PR #36 CI-verified) | Structured circulant-shift base matrix, systematic encoder, normalized min-sum decoder, single-bit syndrome path, and fail-closed convergence checks. This is QC-LDPC, not random sparse LDPC. PR #36 CI run 45214995986 passed 393 tests. |
| Three-lane correction | implemented (E2 reference; PR #36 CI-verified) | Layered QC-LDPC/production-RS, direct production-RS, and separately written bitwise-GF(256) reference-RS lanes. Two-of-three agreement required; accepted output is re-encoded by both RS implementations and QC encoder. Third-party implementation/formal proof remain open. PR #36 CI run 45214995986 passed 393 tests. |
| Chunked content-addressed storage | implemented (E2 reference; PR #36 CI-verified) | SHA-256 chunk objects, canonical immutable manifests, atomic writes, file fsync, best-effort directory fsync, and read-time chunk/manifest/whole-content verification. Physical power-loss durability remains unverified. PR #36 CI run 45214995986 passed 393 tests. |
| Virtual computer/SOS | proposed | isolation and escape-resistance tests |
| Device enrollment and mutual authentication | implemented (E2 reference; PR #38 CI-verified) | Device-signed consent request, operator-signed subset certificate, host-signed challenge, device-signed one-use response, scoped sessions, signed one-use operator revocation, and per-request audit decisions. CRYPTIC CI run 45217416194 and mining-engine run 45217417851 each passed 379 tests. No live radio/network adapter or hardware attestation claim. |
| Device assistant adapters | proposed | live network, BLE, and home-automation adapters; platform keystore integration; hardware attestation; key rotation; multi-host interoperability |
| Local seed and Merkle ledger CLI | implemented (E2) | seven local unit tests pass; repository commit and runtime integration still require CI/integration evidence |
| Crystalline admission lifecycle | proposed (E1) | schemas, deterministic ADAM policy evaluator, signed decisions, negative tests, independent verifier, external checkpoint |
| Four-lane SHA-256 reference mining | implemented (E3 reference) | four disjoint lanes, deterministic affine traversal, independently verified SHA-256 candidates, bounded per-lane hit retention; chain-specific header adapter and production benchmark remain |
| Reversible barrel-roll framing | implemented (E3 reference) | bit/byte/lane inverse and round-trip tests; transforms remain outside consensus preimage |
| ML-KEM-768 suite selection | adopted design | vetted provider, official vectors, authenticated key binding, and interoperability tests |
| ML-DSA-65 suite selection | adopted design | vetted provider, official vectors, key lifecycle, and signature interoperability tests |
| SLH-DSA optional profile | adopted design | provider selection and optional-profile interoperability tests |
| PQ key lifecycle/runtime | proposed | protected key store, rotation, revocation, replay, and recovery tests |
| BLE/home automation | proposed | device-specific authorization and safety tests |

| Supervised whole-request HTTP transport | implemented (E3) | PR #21 mainline integration; spawn-isolated worker covers DNS, TCP, TLS, headers, and body reads; parent-side absolute monotonic deadline, redirect denial, bounded response IPC, worker termination and poisoning; CI evidence required on the rebased branch |
| Four-lane FGR-ICE SHA-256d regtest | implemented (E3 reference) | Four disjoint nonce lanes, center recomputation, finite time budget, optional ML-DSA-65 signed receipt; signing/self-verification are inside the acceptance deadline; no HCCGN network consensus claim |
| PQ transport adapter registry | implemented (E2) | ML-DSA-signed manifests, pinned trust store, explicit KEM/signature capability declarations, authenticated/deadline-gated selection, and signer-revocation invalidation; real network adapters and external trust operations remain unintegrated |
| Negacyclic ring and SHA-256 inverse research | research implementation (E2) | finite arithmetic/research prototypes with tests; not a cryptographic hash inversion claim and not a consensus primitive |

| GCF/1 five-stage completion | implemented (E3 reference; current-mainline CI verified in run 44941497738: 368 tests, 2 skipped; Go vectors and both benchmarks passed) | Independent finality verifier, proposal/vote stages, strict weighted quorum, PREVOTE/PRECOMMIT lock and certificate checks, ADAM/APEX integration; no live validator network claim |
| HCCGN-WORK/1 canonical proof profile | implemented (E3 reference; current-mainline CI verified in run 44941497738: 368 tests, 2 skipped; Go vectors and both benchmarks passed) | 184-byte big-endian header, domain-separated SHA-256, authenticated active-target comparison, content-addressed proof envelope, Python/Go known-answer vectors and midstate/full-hash equivalence; external GOD root and independent monotonic anchor remain deployment gates |
| GCF-P2P/1 direct validator transport | implemented (E2; current-mainline CI verified in run 44941497738: 368 tests, 2 skipped; Go vectors and both benchmarks passed) | Mutual TLS, pinned peer certificate fingerprints, Ed25519 signed envelopes, bounded frames and replay protection; peer discovery/gossip, round-change, live multi-host interoperability and key-custody review remain open |
| ADAM/APEX historical-chain recovery audit | implemented (E3 reference; current-mainline CI verified in run 44941497738: 368 tests, 2 skipped; Go vectors and both benchmarks passed) | State bytes/size/digest validation, contiguous height and parent-state continuity, WAL reopen/rollback tests, and full persisted-chain revalidation; physical power-loss and filesystem durability are not claimed |


Latest GCF/HCCGN current-mainline verification (2026-11-21): workflow run 44941497738 on commit 245687496b49e2b9c58937953fe6caff03b33b94 completed successfully. Python suite: 368 tests, 2 skipped. Independent Go HCCGN-WORK/1 conformance vectors passed. HCCGN midstate kernel: 100,000 hashes in 0.051038959 seconds (1,959,287.61 hashes/second), with full-hash reference match. The bounded SHA-256d benchmark also passed. These are GitHub-hosted runner measurements, not target-device throughput, network target-search rate, or production validator performance.

Update this ledger only with reproducible evidence. Never mark a feature complete because its directory, interface, or design document exists.


## Phase 4 implementation verification — 2026-11-23

At source commit db726ee691c292df4e84777a6ed9f16c604e2206:

- CRYPTIC CI: run 45214995986 — 393 unit tests passed.
- Mining-engine tests: run 45214995960 — 393 unit tests passed; independent Go HCCGN conformance vectors and bounded HCCGN/SHA-256d benchmark steps passed.
- GAIA local trophy mining: run 45214996067 — passed.

| Capability | Status | Evidence and boundary |
|---|---|---|
| GF(256) arithmetic | implemented and CI-verified in PR #36 | Field operations use primitive polynomial 0x11D with inverse, multiplication, division, polynomial operations, and finite-field linear solving. |
| Berlekamp-Welch | implemented and CI-verified in PR #36 | Bounded polynomial recovery rejects inconsistent or non-unique systems and reports corrected evaluation positions. |
| Reed-Solomon | implemented and CI-verified in PR #36 | Non-systematic GF(256) evaluation profile corrects up to floor((n-k)/2) unknown symbol errors; erasure decoding is not claimed. |
| QC-LDPC | implemented and CI-verified in PR #36 | Structured circulant-shift base matrix, identity-circulant parity partition, systematic encoding, normalized min-sum, and verified single-bit syndrome correction. This is QC-LDPC, not random sparse LDPC. |
| Layered correction | implemented and CI-verified in PR #36 | QC-LDPC decoding is followed by Reed-Solomon decoding, syndrome verification, independent re-encoding, and a SHA-256 output receipt. |
| Content-addressed chunk storage | implemented and CI-verified in PR #36 | Immutable SHA-256 chunk objects and canonical manifests; read-time chunk, size, manifest, and whole-content verification. File fsync and best-effort directory fsync are implemented, but physical power-loss durability is not established. |
| Three-lane correction | implemented and CI-verified in PR #36 | Layered QC-LDPC/production-RS, direct production-RS, and separately written bitwise-GF(256) reference-RS decoder. Two-of-three agreement is required; both RS implementations and the QC encoder independently re-encode accepted output. A third-party implementation and formal proof remain open. |

This CI evidence verifies the repository test profile only; it does not establish production deployment, constant-time behavior, formal proof, hardware durability, or cross-platform storage power-loss guarantees.
