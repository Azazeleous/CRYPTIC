# CRYPTIC v1.10 — Canonical Asset Identity and Alias Registry

## Purpose

This increment implements Phase 1 canonical asset identity and collision-safe
alias handling. Ticker symbols, display names, and provider identifiers are
not globally unique asset identities.

## Canonical identity

An asset identity is the tuple of network family (evm or solana), the
lowercase SHA-256 network fingerprint emitted by the normalized chain-head
schema, and a chain-native asset reference. EVM references are 20-byte
contract addresses; Solana references are 32-byte base58 mint addresses.
The explicit native sentinel identifies the network's native asset.

EVM addresses are normalized to lowercase. The versioned canonical identifier
contains all three identity components, so the same contract on different
networks is not treated as the same asset.

## Alias behavior

Symbols, names, and provider IDs are aliases only. Symbols are uppercased;
names are whitespace-collapsed and case-folded; provider IDs require a source
scope. Alias uniqueness is enforced within network family, network
fingerprint, alias type, value, and source scope. A source-specific alias takes
precedence over a global alias for that source. Conflicts are rejected and
missing aliases fail closed. Resolution always requires an explicit network.

## Persistence and API

AssetRegistry uses SQLite. The default database is in-memory for tests and
ephemeral use; supply a filesystem database path for persistence across
process restarts. File-backed databases enable WAL and FULL synchronous mode.
Asset and alias writes are transactional, alias keys are protected by a
composite primary key, and foreign keys prevent orphan aliases. The registry
is thread-safe within one process. Multi-process contention is serialized by
SQLite transactions; network filesystems and multi-host shared-database
deployment are not qualified.

The public API is exported from src.ingestion: AssetIdentity, AssetRecord,
AssetAlias, AssetRegistry, AssetIdentityError, AssetNotFoundError, and
AmbiguousAssetAliasError. AssetIdentity.from_normalized_chain accepts only
the existing normalized chain-head schema; it never infers identity from a
ticker or endpoint.

## Boundaries

The registry does not fetch external metadata, verify contract/mint ownership,
attest issuer identity, or prove a provider-reported mint or contract is honest.
Provider provenance, independent asset verification, multi-host durability,
backup/restore, and complete provider coverage remain open.

## Verification

Tests cover cross-network identity separation, address normalization,
native assets, Solana mint validation, symbol collision, provider-scoped
aliases, alias conflict rejection, unknown alias failure, metadata
immutability, normalized-chain binding, deterministic listing, SQLite
reopen/persistence, and transaction rollback.
