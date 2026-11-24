# CRYPTIC GCF/1 — Infrastructure Decisions

Status: **DECIDED TARGET ARCHITECTURE — NOT DEPLOYED AS A FOUR-VALIDATOR NETWORK**

## 1. Validator topology

Deploy four validator hosts across four independent administrative and infrastructure failure domains. The initial production profile is four equal-weight validators; three affirmative votes are required for a strict >2/3 quorum.

Required separation:
- Four distinct operator organizations and cloud accounts.
- At least two infrastructure providers and at least three geographic regions.
- No shared control plane, shared privileged identity, shared HSM tenancy, or common private network administrator able to control multiple validators.
- Independent power and network paths where the host is physical.
- Each host runs one validator identity only.

A topology that cannot demonstrate these separations is not eligible for production. Four VMs in one cloud account or four processes on one host do not constitute four independent validators.

## 2. Network and transport

- Validator-to-validator traffic uses mutually authenticated TLS 1.3 with a unique certificate per validator and pinned certificate/public-key identity mapping.
- Consensus messages are signed at the application layer independently of transport authentication.
- Use a private overlay or site-to-site WireGuard links only as a routing layer; overlay membership is not validator identity and must not replace application mTLS.
- Deny public unauthenticated consensus ingress. Expose only bounded, rate-limited submission/status endpoints through a separately authenticated edge.
- Enforce per-peer frame size, connection, request-rate, replay, and deadline limits. Do not permit peer-provided addresses or metadata to alter trust configuration.
- Clock synchronization is monitored, but consensus safety never depends on wall-clock agreement. Timeouts may trigger round-change attempts; they never release locks or prove finality.

## 3. Signer and HSM/KMS boundary

Consensus private keys are non-exportable HSM/KMS keys. The HSM/KMS policy must:
1. Permit signing only to one dedicated signing-gateway workload identity per validator.
2. Deny direct signing to CI, operators' interactive identities, Worker credentials, application workloads, and other validators.
3. Restrict the gateway to approved GCF domain-separated message types and the validator's configured network/epoch/identity.
4. Require durable intent recording before invoking the HSM; ambiguous outcomes permit only byte-identical retries.
5. Emit immutable provider audit events for every signing request, denial, key change, and policy change.
6. Require two-person approval for key policy, key rotation, exportability, or destruction changes.

The repository's PersistentGCFVoteSigner is a local guard, not a substitute for HSM-side IAM/network enforcement. A generic KMS Sign(digest) permission alone is insufficient because it cannot prove that the digest represents an authorized GCF message. The signing gateway must validate canonical message structure and policy before it calls the HSM, and the HSM must be unreachable except through that gateway.

## 4. Cloudflare anchor role

The Cloudflare Worker and D1 database are an external sequence-anchor and finality-verification service only. They are not a consensus quorum, validator database, HSM, trust-root authority, or source of independent justice evidence.

Production configuration:
- Keep workers.dev disabled; expose only an explicitly approved custom route.
- Bind D1 using the least-privilege Worker binding.
- Store no validator private keys or HCCGN root private keys in Worker secrets.
- Anchor write authorization is a separate short-lived credential with narrowly scoped issuer, audience, sequence, hash, and expiry constraints.
- The Worker must verify the authorization policy and the exact prior anchor state before advancing sequence/hash. A holder of a bearer token must not be able to choose an arbitrary next hash.
- Keep staging and production accounts/databases separate.
- Retain deployment IDs, Worker version IDs, migration history, and audit events in the release evidence bundle.

The current staging Worker deployment is intentionally dormant. No route, workers.dev access, production secrets, or production anchor token may be enabled by this document.

## 5. D1 schema and migration policy

- SQL migrations are append-only, numbered, reviewed, and idempotent where possible.
- Initialize Wrangler's d1_migrations history through the supported Wrangler migration workflow before production; do not hand-edit the history table to claim a migration ran.
- Apply migrations to a disposable staging database first, then verify schema, row counts, constraints, and restore behavior.
- Back up before production migrations. Migration rollback means restoring a verified backup or applying a forward repair migration; never delete finality or authorization history to make a migration pass.
- Use transaction boundaries for multi-table invariants where supported. If a migration is not atomic in D1, make each step restart-safe and verify each postcondition.

## 6. Monitoring and SLOs

Measure, do not assume:
- Per-validator heartbeat age, process health, signer availability, and storage durability.
- Peer connectivity matrix and authenticated message rejection counts.
- Proposal, PREVOTE, PRECOMMIT, round-change, and finality latency distributions.
- Quorum availability, round-change frequency, timeout causes, and height/round lag.
- HSM latency, denial rates, audit-log delivery lag, and key-policy drift.
- Anchor sequence/hash continuity and Worker/D1 error rates.
- Clock offset, disk pressure, CPU/memory, and restart count.

No capacity, throughput, latency, or availability claim is valid without a measured run with recorded hardware, software, network, load profile, duration, and raw results.

## 7. Required drills

Before activation: network partition, one-validator loss, two-validator loss, signer outage, HSM policy bypass attempt, duplicate/replayed message, database restore, Worker rollback, concurrent anchor update, clock skew, process restart, and witnessed hard power-loss durability tests. A drill must record expected outcome, observed outcome, evidence digest, operators, and independent witness.

## 8. Current deployment facts

The known Cloudflare staging Worker is deployed but dormant, with D1 bound and schema tables initialized. It has no production route, no workers.dev exposure, and no production secrets. The Wrangler migration-history table remains uninitialized. No four-validator topology or HSM-side policy is asserted as deployed.
