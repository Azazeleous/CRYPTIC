# CRYPTIC Architecture

## System layers

1. **Source layer** — HTTP, WebSocket, JSON-RPC, exchange APIs, public registries, local files, and enrolled device protocols.
2. **Adapter layer** — source-specific authentication, pagination, rate limits, retries, schema validation, and provenance capture.
3. **Ingestion layer** — bounded streaming, backpressure, deduplication, timestamp normalization, and immutable raw observations.
4. **Canonical data layer** — normalized assets, chains, markets, devices, capabilities, events, and evidence records.
5. **Verification layer** — identity checks, cross-source comparison, integrity checks, freshness, anomaly detection, and uncertainty.
6. **Mining layer** — chain-specific canonical header construction, deterministic candidate scheduling, four disjoint worker lanes, proof verification, and performance telemetry.
7. **Cryptography layer** — authenticated identities, ML-KEM session establishment, ML-DSA checkpoint signatures, optional SLH-DSA profiles, key derivation, and authenticated encryption.
8. **Model layer** — inference, retrieval, planning, tool selection, learning/evaluation, and model routing.
9. **Extension layer** — capability manifests, sandboxed execution, conformance tests, permission grants, and lifecycle management.
10. **Storage layer** — content-addressed objects, manifests, indexes, chunking, replication, and recovery.
11. **Device/SOS layer** — enrolled-device assistant and isolated virtual computer with explicit mount and network boundaries.
12. **Operator layer** — API, web console, audit views, and human approvals.

## Mining and cryptographic separation

Mining workers hash each canonical candidate independently. The four-lane scheduler owns disjoint candidate ordinals and records traversal direction. Reversible bit, byte, and lane rotations are framing/scheduling operations only; they never alter a chain's consensus preimage or target.

Post-quantum cryptography authenticates lane identities, establishes session secrets, protects lane messages, and signs durable checkpoints. It is not a replacement for the consensus proof-of-work hash and is not performed for every nonce.

## Control plane and data plane

The control plane manages configuration, enrollment, capability grants, policies, model/extension registries, cryptographic identities, and audit events. The data plane carries bounded observations and computation payloads. Data-plane messages cannot silently modify control-plane policy.

## Capability lifecycle

Discover → inspect provenance → parse manifest → resolve dependencies → static scan → sandbox → conformance tests → permission review → human approval where required → register → monitor → revoke/rollback.

## Runtime status vocabulary

- proposed
- scaffolded
- implemented
- unit-tested
- integration-tested
- security-reviewed
- production-verified

A status advances only with recorded evidence.
