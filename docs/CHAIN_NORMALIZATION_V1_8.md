# CRYPTIC v1.8 — Canonical Chain Identity and Discrepancy Reports

## Purpose

v1.8 converts raw EVM and Solana adapter observations into a provider-neutral
chain-head representation and compares independent observations only when
they establish the same network identity.

## Network identity

An EVM chain identity is derived from both:

- Numeric `chain_id`.
- The genesis block hash.

This avoids treating two unrelated EVM networks as identical merely because
they reuse the same chain ID.

A Solana cluster identity is derived from its genesis hash. EVM and Solana
identities are domain-separated by family. Identity is a deterministic
fingerprint of the reported genesis anchor; this module does not independently
validate consensus or establish that an endpoint is honest.

## EVM observation extension

The EVM adapter now reads:

- `eth_chainId`.
- `eth_getBlockByNumber("0x0", false)` for the genesis anchor.
- `eth_getBlockByNumber("latest", false)` for the current reported head.

It validates block number, timestamp, block hash, and parent hash. The
observation now carries `chain_id`, `genesis_hash`, `block_number`,
`block_hash`, `parent_hash`, and `timestamp`.

The Solana adapter continues to report genesis hash, finalized slot, and
finalized block height.

## Normalization

`normalize_chain_observation` accepts one source observation and returns
`cryptic.normalized-chain-head.v1`. `normalize_journal_record` converts one
already-audited raw journal record containing exactly one source item.

Normalization is strict: unknown source schemas, malformed genesis anchors,
invalid heights, and inconsistent network identity fields fail closed.
It does not infer missing chain IDs, genesis hashes, or block hashes.

## Cross-source discrepancy analysis

`compare_chain_heads` groups only observations with the same independently
derived network identity. It rejects duplicate source IDs within one network
comparison and reports:

- `height_lag` when source heights differ by more than the configured bound.
- `head_hash_conflict` when sources report different hashes at the same
  observed height.

Observations whose timestamps exceed the configured skew window are skipped,
not labeled as disagreements. Defaults are a 15-second observation-skew
window and a one-block height tolerance. Reports include whether evidence was
sufficient to compare at least one group and a deterministic SHA-256 digest.

## Important interpretation limits

- A provider-reported genesis hash is an identity anchor, not proof of honest
  execution or consensus validity.
- Observation timestamps are source metadata, not trusted time.
- A height lag can reflect provider latency or different observation moments;
  it is not by itself proof of a fork.
- A same-height hash conflict is a discrepancy requiring independent review,
  not an automatic declaration that one source is malicious.
- Groups with fewer than two independent source IDs or excessive timestamp
  skew are not compared.
- No network writes, transaction submission, signing, or wallet operations
  are implemented.

## Verification

Unit tests cover identity separation, schema validation, journal-record
normalization, height lag, same-height hash conflict, timestamp-skew handling,
duplicate source rejection, tampered identity rejection, and deterministic
report output.
