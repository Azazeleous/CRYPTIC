# CRYPTIC Production Gate Runbook v1

This runbook distinguishes deployable software from external authority and hardware evidence. The repository does not manufacture GOD authorization, trust-root pins, validator keys, policy evidence, or durability claims.

## Gate 1 — GOD-authorized Ed25519 trust root

**Software delivered:** load_independently_pinned_root() validates a public root-pin record against a fingerprint supplied through a separate trusted channel. GODHTTPSGate accepts only a short-lived, request-bound Ed25519 decision from a separately pinned signer. GODNetworkAuthorizer remains the final GCF adapter and fails closed if GOD does not explicitly allow gcf.consensus.propose.

**Deployment requirements:**
1. GOD governance creates/authorizes the root and the exact capability gcf.consensus.propose; this is an upstream GOD policy change, not a CRYPTIC-local allowlist edit.
2. Transfer the public key and SHA-256 fingerprint through two independent authenticated channels. Do not copy the fingerprint from the same file or repository as the key.
3. Provision the pin record:
   {"schema":"CRYPTIC-GOD-ROOT-PIN/1","signer_id":"<GOD signer id>","public_key_hex":"<64 lowercase hex chars>"}
4. Provision the independently obtained fingerprint to the verifier as expected_fingerprint.
5. Configure the actual GOD decision endpoint. Its signed response must implement CRYPTIC-REMOTE-DECISION/1, bind the canonical request hash and request nonce, and expire within 300 seconds.
6. Verify a positive authorization and a negative authorization from GOD itself. A local test key is not production evidence.

**Still external:** GOD root authorization, out-of-band fingerprint ceremony, root rotation/recovery approvals, and the actual GOD policy deployment. Never replace them with a generated test key.

## Gate 2 — Independent monotonic sequence anchor

**Software delivered:** HTTPSSequenceAnchor implements a signed HTTPS read and atomic compare-and-swap write client. HCCGNActiveTargetPolicy can require this provider and fails closed when it is absent or inconsistent.

**Required service contract:**
- GET /v1/anchors/{network_id} returns HTTP 404 if uninitialized, otherwise a signed CRYPTIC-SEQUENCE-ANCHOR/1 record.
- PUT initializes with If-None-Match: *; subsequent updates use If-Match: "<sequence>:<policy_hash>".
- The service atomically compares the expected old tuple and commits the new (sequence, policy_hash) tuple. HTTP 409/412 means conflict.
- The response is signed by a separately pinned anchor key. The service must reject sequence rollback and same-sequence hash replacement.
- The anchor storage and signing authority must be outside the validator host and outside the HCCGN SQLite database backup/restore domain.

**Deployment requirements:** provision the actual HTTPS service, signer key, independent public-key pin, access policy, backups, availability monitoring, and disaster-recovery process. Configure require_external_anchor=True. Test concurrent writers, stale clients, node restore from an old disk image, anchor outage, and service restore. Any ambiguity must deny policy resolution.

**Still external:** a live separately administered anchor service and proof that its state cannot be rolled back with the validator host.

## Gate 3 — GAIA-JUSTICE policy and evidence providers

**Software delivered:** HTTPSJusticeProviders supplies two distinct, independently pinned SignedHTTPSDecisionClient instances. The existing JusticeEvidenceVerifier continues to require both policy and evidence decisions to be exactly True.

Each provider signs a response bound to the exact request digest, signer identity, request nonce, and a short validity window. The policy provider must independently retrieve the policy/audit material. The evidence provider must independently retrieve the evidence root, transition, accounting, and challenge-state material. A digest-shaped string alone is never evidence.

**Deployment requirements:**
1. Deploy separate policy and evidence authorities with distinct signing keys and operational ownership.
2. Bind the complete commitment and proposal digest to each request.
3. Require provider-side provenance, source identity, freshness, revocation, and audit checks before returning decision=true.
4. Test denial, stale response, wrong signer, wrong nonce, replay, policy/evidence disagreement, provider outage, and key rotation.
5. Do not let either service accept its own output as the only evidence for the other.

**Still external:** real GAIA-JUSTICE services, authoritative datasets, policy interpretation, provenance review, and independent audit.

## Gate 4 — Multi-host validator interoperability and key custody

**Software delivered:** GCF-P2P/1 provides mutual TLS, certificate fingerprint allowlisting, signed Ed25519 envelopes, bounded frames, and durable replay protection. HTTPSHSMEd25519Signer is a remote signing boundary that requires mTLS and locally verifies every signature against the validator's pinned public key. make_proposal_with_signer() and make_vote_with_signer() avoid exporting raw validator private keys into the GCF process.

**Deployment requirements:**
1. Assign each validator a unique identity and independent Ed25519 key. Never reuse one test key across validators.
2. Generate/hold production private keys in approved HSM/KMS hardware or a reviewed isolated signer service. The signer endpoint must require mTLS, authorization by validator identity, rate limits, audit records, rotation, revocation, and backup/recovery controls.
3. Publish a validator set whose public keys and weights are authenticated by the GOD governance process.
4. Issue separate mTLS client/server certificates with correct SAN/EKU, trusted CA chains, and per-peer certificate fingerprints. Protect private TLS keys independently.
5. Deploy at least four validators across independently administered hosts/failure domains. Configure network firewall rules, peer allowlists, clock monitoring, persistent replay databases, and independent logs.
6. Run proposal, PREVOTE, PRECOMMIT, finality, node restart, peer outage, partition, equivocation, certificate rotation, signer outage, and recovery drills. Record each node's accepted certificate digest and compare.
7. Verify quorum safety and liveness under the configured validator weights. A loopback CI test is not multi-host evidence.

**Still external:** real hosts, production validator keys, HSM custody attestation, network paths, independent operators, and successful live multi-host drills.

## Gate 5 — Physical power-loss and filesystem durability

**Software delivered:** ADAM uses SQLite WAL with synchronous=FULL, verifies the complete commit chain on reopen, and now has a process-kill test that kills a writer during an uncommitted transaction, verifies rollback, then verifies a committed state after reopen.

**Important:** process termination is not power-loss testing. It does not simulate volatile controller caches, device firmware behavior, filesystem journal loss, sudden power removal, or storage corruption.

**Required hardware test campaign:**
1. Record host model, storage model/firmware, filesystem, mount options, kernel, SQLite version, power-protection features, and UPS configuration.
2. Use a disposable test device and a reproducible workload that continuously commits sequence-numbered states and receipts.
3. Have a qualified hardware-test lab perform controlled power-interruption tests with approved equipment at defined transaction/checkpoint boundaries. Do not manually manipulate mains power, open power supplies, or run this against production devices or data.
4. On every restart, require verify_chain() to pass and compare the recovered head against an independently recorded external checkpoint.
5. Repeat across cold boot, abrupt power removal, full-disk, I/O error, filesystem remount, and backup restoration scenarios.
6. Record raw logs, hashes, timestamps, hardware identity, failure injection point, and recovery outcome. Independent reviewer signs the report.
7. Reject any recovered chain that is truncated, forked, or inconsistent with the external anchor.

**Still external:** actual physical power interruption, storage-controller validation, filesystem review, and an independently signed durability report.

## Current evidence and activation rule

CI contract tests verify the client cryptography, request binding, anchor compare-and-swap semantics, remote signer output, mutual-TLS loopback transport, and ADAM process-crash recovery. They do not certify external services or production hardware.

Production activation is permitted only when all five gates have signed, independently reviewable evidence. Until then, configure all missing providers as absent and keep proposal acceptance fail-closed.
