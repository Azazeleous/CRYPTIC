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
- Device enrollment and mutual authentication.
- Scoped network, BLE, and home-automation bridges.
- Per-device policy, consent, revocation, and audit.

No phase is considered complete without tests and evidence in the capability ledger.


## Phase 7 — GCF consensus and ADAM/APEX acceptance

- GCF/1 proposal/vote engine, strict weighted quorum, vote locks, PREVOTE/PRECOMMIT and finality certificate — implemented and CI-verified after PR #28.
- Independent finality verifier — added as a separate implementation; ADAM/APEX consumes it; branch CI pending.
- HCCGN proof-provider adapter — implemented fail-closed; canonical network header/digest/target specification and known-answer vectors remain a blocking dependency.
- GOD and GAIA-JUSTICE adapters — fail-closed contracts exist; production policy/evidence providers and GOD capability authorization remain open.
- ADAM/APEX transactional commitment and recovery — implemented; HTTP commit/head/recovery routes added; branch CI pending.
- Direct validator peer transport — mutual TLS, peer certificate allowlist, signed envelopes and replay protection added; peer discovery/gossip, round changes, live multi-node interoperability and security review remain open.
- Conformance tests — independent certificate, canonical serialization, peer, HTTP, ADAM and recovery tests added; branch CI pending.

Phase 7 is not production-complete until the canonical HCCGN profile is independently implemented and vectors pass, GOD and justice providers are connected, validator liveness/recovery is tested across real nodes, and ADAM durability/security review is complete.
