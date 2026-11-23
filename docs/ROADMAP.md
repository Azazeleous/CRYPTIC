# Roadmap

## Phase 0 — Repository and evidence foundation
- Establish directory contracts and documentation.
- Inventory existing source artifacts and hashes.
- Record provenance, licenses, dependencies, and unresolved claims.
- Establish CI, formatting, type checking, and test conventions.

## Phase 1 — Read-only source connectivity
- Source registry and adapter interface — implemented and CI-verified in PR #11; provider-specific integrations remain open.
- Public market-data catalogues and quotes.
- EVM and Solana read-only JSON-RPC identity adapters — implemented and CI-verified in PR #12; live endpoint verification, log/history pagination, and subscriptions remain open.
- Health probes, rate limits, reconnect, pagination, provenance — transport timeout/retry and per-client request spacing are implemented; persistent health history, provider-level rate-limit coordination, and raw observation provenance remain open.
- Canonical chain and asset identity; coverage reports.

## Phase 2 — Ingestion and verification
- Bounded streaming and backpressure.
- Tamper-evident raw observation journal — implemented and CI-verified in PR #13; canonical JSONL, hash chain, append locking, fsync, and full-chain audit are available. It is not privileged-proof/WORM storage.
- Canonical EVM/Solana chain-head normalization and cross-source discrepancy reports — implemented and CI-verified in PR #14; comparisons are bounded by identity anchors and observation skew. Asset normalization remains open.
- Deterministic journal replay and data-quality reporting — implemented and CI-verified in PR #15; replay is offline, read-only, reproducible, and fails closed on journal integrity errors.
- Bounded ingestion coordinator — partial v2.0 foundation, v2.0.1 accounting corrections, v2.1 shared-deadline JSON-RPC groundwork, and v2.1.1 regression coverage are CI-verified in PRs #16–#19. Fixed worker/submission-window bounds, page/observation budgets, timeout classification, deterministic single-writer journal append, elapsed-time reporting, and replay integration are covered. Regression tests verify rate-gate wait bounds, retry-backoff budget checks, socket timeout selection, and one shared deadline across EVM/Solana multi-call observations. Those adapters deliberately remain ineligible for runtime execution (`deadline_enforced = False`) until DNS resolution is isolated; journal fsync/audit/replay remain outside the hard deadline.

## Phase 3 — Core model
- Provider-independent model interface.
- Local inference runtime and optional remote providers.
- Retrieval, planning, tool contracts, evaluation harness.
- Learning from curated, licensed, privacy-reviewed evidence.

## Phase 4 — Error correction and storage
- GF(256) primitives and Reed–Solomon implementation.
- Berlekamp–Welch decoder and adversarial tests.
- QC-LDPC encoder/decoder with documented parity-check construction.
- Three-lane correction and independent reverification.
- Chunk manifests, content addressing, integrity, recovery.

## Phase 5 — Extensions and SOS
- Extension manifest and sandbox.
- Virtual computer, terminal, filesystem and process boundaries.
- Capability grants and audit.
- Operator-visible virtual computer.

## Phase 6 — Device assistant
- Device-signed enrollment requests, explicit consent, operator-signed approval certificates, and host/device challenge-response — implemented and CI-verified in PR #38 (379 tests passed).
- Per-device read-only capability grants, exact resource scopes, bounded sessions, one-use challenges, and revocation — implemented and CI-verified in PR #38 (379 tests passed).
- SQLite device registry and hash-linked audit events for enrollment, challenge issuance, authentication, authorization, and revocation — implemented and CI-verified in PR #38 (379 tests passed).
- Live network, BLE, and home-automation adapters; platform keystore integration; hardware attestation; key rotation; and multi-device interoperability remain open.

## Phase 7 — Supervised transport and cryptographic binding
- Whole-request HTTP execution in an isolated, prestarted worker with an absolute monotonic deadline covering DNS, TCP, TLS, headers, and response reads.
- Bounded IPC and response sizes, redirect denial, worker termination on timeout, and runtime poisoning after a completed RPC deadline failure.
- Direct health probes use one-shot workers and close them on every exit path.
- Four-lane FGR-ICE regtest with independent center verification and optional ML-DSA-65 receipt signing inside the acceptance budget.
- Explicit PQ transport adapter manifests, pinned signer trust, declared KEM/signature capabilities, and revocation-aware adapter invalidation.
- Provider interoperability, Windows spawn verification, production trust-root operation, and live endpoint verification remain open.

## Phase 8 — GCF consensus, HCCGN proof, and ADAM/APEX finality
- Independent GCF/1 certificate verifier reconstructs canonical serialization, checks Ed25519 signatures, validator-set digest, PREVOTE/PRECOMMIT weighted quorum, lock references, and certificate metadata.
- HCCGN-WORK/1 defines a new normative 184-byte binary header, domain-separated SHA-256 proof digest, proof-envelope commitment, authenticated active-target policy, content-addressed proof store, and independent Python/Go known-answer verification.
- Midstate mining hashes the invariant first 128 bytes once and is cross-checked against full SHA-256; this is kernel throughput, not network target-search capacity.
- Direct GCF-P2P/1 peer transport provides mutual TLS, pinned peer identities, signed envelopes, bounded frames, and replay protection; it is not yet a complete production BFT mesh.
- ADAM/APEX acceptance uses independent finality verification, transactional state commitments, contiguous-height/parent-state checks, WAL recovery, and historical-chain integrity verification.
- GOD network authorization, GAIA-JUSTICE policy/evidence services, a genuinely independent monotonic anti-rollback anchor, physical power-loss durability review, live multi-host validator interoperability, and key-custody security review remain external production gates. Missing providers continue to fail closed.

No phase is considered complete without tests and evidence in the capability ledger.
