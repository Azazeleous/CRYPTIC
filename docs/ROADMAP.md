# Roadmap

## Phase 0 — Repository and evidence foundation
- Establish directory contracts and documentation.
- Inventory existing source artifacts and hashes.
- Record provenance, licenses, dependencies, and unresolved claims.
- Establish CI, formatting, type checking, and test conventions.

## Phase 1 — Read-only source connectivity
- Source registry and adapter interface.
- Public market-data catalogues and quotes.
- EVM JSON-RPC and Solana RPC adapters.
- Health probes, rate limits, reconnect, pagination, provenance.
- Canonical chain and asset identity; coverage reports.

## Phase 2 — Ingestion and verification
- Bounded streaming and backpressure.
- Immutable raw observation log.
- Normalization and cross-source discrepancy records.
- Deterministic replay and data-quality tests.

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
