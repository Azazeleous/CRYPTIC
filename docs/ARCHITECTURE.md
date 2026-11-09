# CRYPTIC Architecture

## System layers

1. **Source layer** — HTTP, WebSocket, JSON-RPC, exchange APIs, public registries, local files, and enrolled device protocols.
2. **Adapter layer** — source-specific authentication, pagination, rate limits, retries, schema validation, and provenance capture.
3. **Ingestion layer** — bounded streaming, backpressure, deduplication, timestamp normalization, and immutable raw observations.
4. **Canonical data layer** — normalized assets, chains, markets, devices, capabilities, events, and evidence records.
5. **Verification layer** — identity checks, cross-source comparison, integrity checks, freshness, anomaly detection, and uncertainty.
6. **Model layer** — inference, retrieval, planning, tool selection, learning/evaluation, and model routing.
7. **Extension layer** — capability manifests, sandboxed execution, conformance tests, permission grants, and lifecycle management.
8. **Storage layer** — content-addressed objects, manifests, indexes, chunking, replication, and recovery.
9. **Device/SOS layer** — enrolled-device assistant and isolated virtual computer with explicit mount and network boundaries.
10. **Operator layer** — API, web console, audit views, and human approvals.

## Control plane and data plane

The control plane manages configuration, enrollment, capability grants, policies, model/extension registries, and audit events. The data plane carries bounded observations and computation payloads. Data-plane messages cannot silently modify control-plane policy.

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
