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
