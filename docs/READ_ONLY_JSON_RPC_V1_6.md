# CRYPTIC v1.6 — Read-only EVM and Solana JSON-RPC

## Purpose

This increment adds a bounded HTTP JSON-RPC 2.0 transport and two concrete
read-only chain identity adapters. It advances the Phase 1 connectivity
roadmap without adding transaction submission, signing, wallet operations,
or state-changing provider calls.

## Transport contract

`JsonRpcClient` provides:

- HTTPS endpoints, with HTTP permitted only for loopback development hosts.
- Endpoint validation that rejects embedded credentials, query strings, and
  fragments.
- JSON-RPC 2.0 request IDs and strict response-envelope / ID validation.
- A bounded response body (default 1 MiB; configurable maximum 8 MiB).
- A bounded request timeout (default 8 seconds; maximum 30 seconds).
- A per-client, thread-safe request-spacing gate.
- At most three retries, with bounded exponential delay, for transport
  failures, HTTP 429, and HTTP 5xx.
- Redirect rejection to prevent a configured endpoint from silently moving
  the request to another host.
- A global allowlist of read-only methods. The transport rejects arbitrary
  method names and does not permit transaction or account mutation methods.

The transport uses only the Python standard library. It does not provision
credentials. Public RPC endpoints are expected; provider-specific secret
management is a separate future integration.

## EVM adapter

`EvmReadOnlyAdapter` currently exposes:

- `eth_chainId` — numeric chain identity.
- `eth_blockNumber` — current reported head height.

Quantities are parsed from canonical hexadecimal JSON-RPC values and returned
as integers. The adapter emits one bounded observation under schema
`cryptic.evm-chain-observation.v1`.

## Solana adapter

`SolanaReadOnlyAdapter` currently exposes:

- `getGenesisHash` — cluster identity.
- `getSlot` at finalized commitment.
- `getBlockHeight` at finalized commitment.

The adapter validates the genesis hash and non-negative integer head values,
then emits one bounded observation under schema
`cryptic.solana-chain-observation.v1`.

## Registry integration

Both adapters implement the v1.5 `SourceAdapter` contract and can be
registered with `SourceRegistry`. Each emits a single unpaginated observation.
The registry and adapters remain local components; no source is automatically
enrolled or queried at import time.

## Verification

Unit tests validate JSON-RPC envelopes, IDs, error objects, response bounds,
endpoint policy, timeout/retry policy, read-only method restrictions, adapter
schemas, and registry compatibility.

Optional live integration tests execute real read-only RPC requests when
`CRYPTIC_EVM_RPC_URL` or `CRYPTIC_SOLANA_RPC_URL` is explicitly provided.
They are skipped when those variables are absent. CI passing without those
variables proves protocol and contract tests, not live provider availability.

## Not yet implemented

- EVM log/block pagination and bounded range scans.
- Solana address-history pagination and WebSocket subscriptions.
- Provider catalogues, endpoint discovery, credential vaults, and shared
  cross-process rate limiting.
- Persistent health history, reconnection orchestration, and raw observation
  provenance.
- Cross-provider chain identity reconciliation.

No claim of complete chain coverage, provider SLA, consensus validation, or
network acceptance is made.
