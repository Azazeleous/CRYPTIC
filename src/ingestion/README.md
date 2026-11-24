# ingestion

Bounded stream ingestion, pagination, backpressure, deduplication, and raw observation capture.

## Read-only JSON-RPC

The `json_rpc` module provides a bounded JSON-RPC transport and EVM/Solana
chain identity adapters. See
`docs/READ_ONLY_JSON_RPC_V1_6.md` for the allowlist, limits, optional live
checks, and explicit exclusions.

## Raw observation journal

`observation_log` appends validated `SourcePage` records to a canonical
JSONL SHA-256 chain. It verifies the journal before append and on retrieval.
See `docs/RAW_OBSERVATION_JOURNAL_V1_7.md` for its threat model and limits.

## Chain normalization

`normalization` derives provider-neutral EVM/Solana chain identities from
genesis anchors and compares fresh observations across independent sources.
See `docs/CHAIN_NORMALIZATION_V1_8.md` for the discrepancy semantics and
interpretation limits.

## Deterministic replay

`replay` re-audits a raw journal, normalizes supported records, detects data
quality issues, and runs cross-source discrepancy analysis without network
calls or journal mutation. See `docs/DETERMINISTIC_REPLAY_V1_9.md`.


## Bounded ingestion runtime v2.0

The runtime coordinates deadline-aware adapters with bounded workers, queue admission, page/observation/time budgets, one deterministic journal-writer path, per-source health accounting, and offline replay. See docs/BOUNDED_INGESTION_RUNTIME_V2_0.md for the adapter deadline contract and current compatibility limits.

## Canonical asset identity

The asset_identity module provides SQLite-backed network-scoped canonical asset identifiers and collision-safe symbol, name, and provider-ID aliases. File-backed registries persist across process restarts. Symbols are never treated as globally unique identifiers. See docs/CANONICAL_ASSET_IDENTITY_V1_10.md for the schema and boundaries.
