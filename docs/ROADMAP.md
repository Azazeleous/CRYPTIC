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
- Bounded ingestion coordinator — PRs #16–#19 established bounded workers, submission windows, budgets, timeout accounting, deterministic single-writer journal append, replay integration, and shared-deadline propagation. PR #20 added a standalone supervised DNS resolver. v2.3 replaces the remaining in-process HTTP path for deadline-aware JSON-RPC calls with a prestarted, spawn-based whole-request worker covering DNS, TCP, TLS, headers, and body reads. Parent-side IPC waits use the absolute monotonic deadline; timeout terminates and permanently poisons the worker. Redirects are denied, response reads are capped, and standard TLS hostname/certificate validation is retained. Worker preparation occurs before `collection_started`; PR #21 CI run 44826272286 passed unit tests and bounded benchmark. Journal fsync/audit/replay remain outside the source-collection deadline. Windows spawn CI and live provider verification remain open.

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
