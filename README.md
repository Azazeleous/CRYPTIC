# CRYPTIC

CRYPTIC is a source-grounded, extensible model and runtime. This repository is its canonical architecture, implementation, evidence, and operational record.

## Principles

- Evidence before claims: distinguish proposed, implemented, tested, integrated, and production-verified.
- Provenance on every ingested observation: source, retrieval time, schema, integrity digest, and verification state.
- Least privilege: enrolled devices, scoped capabilities, explicit grants, auditability, and revocation.
- Local-first where practical: local models and public endpoints can operate without provider keys; protected services still require authorization.
- Remedy-driven reliability: classify, match a remedy, apply within policy, independently verify, and document. Unknown remedies are proposals until tested.
- Reproducibility: pin dependencies and model/data revisions; checksum artifacts and record experiments.
- Safe extension absorption: inspect, describe, sandbox, test, review permissions, then register. Learning code does not grant privileges.
- Measurable coverage: “all assets/networks/extensions” is a coverage objective measured against explicit inventories, never an unsupported completeness claim.
- Consensus integrity: mining schedulers and reversible data transforms never change a chain's canonical proof-of-work rules.
- Cryptographic separation: post-quantum key establishment and signatures protect identities, sessions, and records; they do not replace proof-of-work.

## Repository map

| Directory | Responsibility |
|---|---|
| docs | architecture, requirements, decisions, security, API, operations, research |
| src | core runtime, ingestion, normalization, verification, reasoning, learning |
| adapters | market, chain, exchange, model, storage, device, and protocol connectors |
| models | model interfaces, training, evaluation, inference, registry |
| extensions | manifests, adapters, sandboxing, extension tests |
| storage | chunk store, manifests, indexes, backends, recovery |
| error-correction | GF(256), Reed–Solomon, QC-LDPC, Berlekamp–Welch, reverification |
| mining | four-lane scheduler, reversible barrel-roll framing, SHA-256 reference miner |
| cryptography/pq | provider boundary and PQ algorithm-suite contract |
| device | enrollment, assistant, discovery, BLE, device bridges |
| sos | isolated virtual computer, terminal, filesystem, mounts, process model |
| web | operator application, visual computer, canvas, assets |
| tests | unit, integration, conformance, security, recovery, property tests |
| ops | deployment, observability, backup, restore, maintenance |
| scripts | reproducible developer and maintenance commands |
| configs | validated example configuration; never secrets |

## Current status

The four-lane reference miner, reversible barrel-roll framing, and PQ suite architecture are recorded on the feature/four-lane-mining-pq branch. The reference miner is not yet a coin-specific consensus adapter or production pool client. PQ algorithms are selected, but a vetted provider and runtime key lifecycle remain to be integrated. Directory creation does not imply implementation. See the capability ledger, roadmap, mining architecture, and verification policy.

## Security

Never commit API tokens, private keys, seed phrases, passwords, device credentials, or private user data. Use OS credential stores or explicitly configured secret providers. All device and filesystem access must be enrolled, scoped, logged, and revocable. PQ operations must use vetted provider implementations; CRYPTIC must not implement standardized cryptographic primitives from scratch.
