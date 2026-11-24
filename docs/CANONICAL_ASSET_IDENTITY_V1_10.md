# CRYPTIC v1.10 — Canonical Asset Identity and Alias Registry

## Purpose

This increment implements the Phase 1 canonical asset identity capability.
Ticker symbols, display names, and provider identifiers are not globally
unique asset identities.

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

## API

The public API is exported from src.ingestion: AssetIdentity, AssetRecord,
AssetAlias, AssetRegistry, AssetIdentityError, AssetNotFoundError, and
AmbiguousAssetAliasError. AssetIdentity.from_normalized_chain accepts only
the existing normalized chain-head schema; it never infers identity from a
ticker or endpoint.

## Boundaries

The registry is thread-safe and deterministic but process-local and in-memory.
It does not persist asset records, fetch provider metadata, verify token
contracts, attest issuer identity, or prove a provider-reported mint or
contract is honest. Those capabilities require provenance, independent
verification, and durable registry operations.

## Verification

Tests cover cross-network identity separation, address normalization,
native assets, Solana mint validation, symbol collision, provider-scoped
aliases, alias conflict rejection, unknown alias failure, metadata
immutability, normalized-chain binding, and deterministic listing.
