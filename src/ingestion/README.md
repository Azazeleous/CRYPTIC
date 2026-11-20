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
