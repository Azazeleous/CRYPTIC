# CRYPTIC Production Gate Runbook v1

This runbook distinguishes deployable software from external authority and hardware evidence. The repository does not manufacture GOD authorization, trust-root pins, validator keys, policy evidence, or durability claims.

## Upstream G.O.D. repository boundary

The public `machackabook/G.O.D.` repository is G.O.D. v5.0.1: a browser capability detector, explicit-consent gate, optional read-only Chrome companion, and local evidence-receipt interface. Its published architecture explicitly places a future authenticated SYNAPSE gateway outside that repository. It is **not** the authoritative GOD governance policy service, trust-root issuer, or signed decision endpoint required by this runbook. The cross-repository interface and evidence map is documented at [G.O.D. — CRYPTIC production-gate integration](https://github.com/machackabook/G.O.D./blob/main/docs/CRYPTIC-PRODUCTION-GATE-INTEGRATION.md).

Consequently, the public G.O.D. repository update documents the boundary only; it does not satisfy Gate 1, grant `gcf.consensus.propose`, or change the current fail-closed result. A separate authoritative GOD policy service/repository and independently distributed trust-root evidence are still required.


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

**Software delivered:** HTTPSSequenceAnchor implements signed HTTPS reads and atomic compare-and-swap writes. Every write now requires a GOD-signed `CRYPTIC-GOD-POLICY-TRANSITION/1` authorization envelope. The Worker verifies that signature against a separately pinned GOD Ed25519 public key and exact signer/policy IDs before any anchor mutation. HCCGNActiveTargetPolicy can require this provider and fails closed when it is absent or inconsistent.

**Required service contract:**
- GET /v1/anchors/{network_id} returns HTTP 404 if uninitialized, otherwise a signed CRYPTIC-SEQUENCE-ANCHOR/1 record.
- PUT initializes with If-None-Match: *; subsequent updates use If-Match: "<sequence>:<policy_hash>".
- The service atomically compares the expected old tuple and commits the new (sequence, policy_hash) tuple. HTTP 409/412 means conflict.
- The response is signed by a separately pinned anchor key. The service must reject sequence rollback and same-sequence hash replacement.
- Every PUT carries a GOD authorization binding capability `cryptic.sequence_anchor.advance`, policy ID, network ID, expected old sequence/hash, proposed new sequence/hash, signer ID, issued/expiry times, and a one-time nonce. The Worker rejects missing, invalid, expired, mismatched, or replayed proofs before writing.
- The bearer token is transport authentication only. It cannot authorize a policy transition. The GOD private key is never provisioned to the validator host or anchor Worker; only its independently pinned public key is provisioned to the Worker.
- The anchor storage and signing authority must be outside the validator host and outside the HCCGN SQLite database backup/restore domain.

**Write authentication and policy authorization:** the CRYPTIC client refuses sequence advancement unless both a transport write credential and a GOD-signed transition envelope are supplied. The credential is transport authentication only; it is not policy authority. Supply a random secret of at least 32 non-whitespace characters through `CRYPTIC_SEQUENCE_ANCHOR_TOKEN` or the constructor's `write_token=` argument. It is sent only on PUT as `Authorization: Bearer <token>`; signed GET reads do not transmit it. The Worker must store the matching value as a Cloudflare secret named `ANCHOR_WRITE_TOKEN`, compare it in constant time before processing any write, and reject missing or invalid credentials with HTTP 401. Never commit the token, put it in a URL or command-line argument, log it, or store it in D1. Rotate it through an authenticated operator procedure. Response signatures do not replace caller authentication.

**Deployment requirements:** provision the actual HTTPS service, signer key, independent public-key pin, access policy, backups, availability monitoring, and disaster-recovery process. Configure require_external_anchor=True. Test concurrent writers, stale clients, node restore from an old disk image, anchor outage, and service restore. Any ambiguity must deny policy resolution.

**Worker implementation delivered:** `cloudflare/sequence-anchor/src/index.js` verifies the GOD transition envelope before mutation, persists one-time authorization nonces in D1, then uses the conditional D1 UPSERT as the anchor compare-and-swap linearization point. The second migration creates the replay-receipt table. The request bearer token is not sufficient to advance the anchor. The D1 migration and Wrangler configuration are in `cloudflare/sequence-anchor/`. Its Wrangler configuration sets `workers_dev = false` and defines no route. The Worker was uploaded on 2026-11-22 to Cloudflare account `bc67ed84864df46b05d196cff28126bb` as `cryptic-production-sequence-anchor` (deployment `697e0e25b28a4e109eda04dd98769e1b`; tag `f4b9f90848404d10ac3efdb1f701d762`) with D1 binding `ANCHOR_DB` to database `1d6199f8-8a49-45c4-abd6-ac816a91a487`. Verification confirmed Workers.dev disabled, no zone route targeting this Worker, and an existing empty `anchors` table. Signing/write secrets and GOD public-key/policy configuration are not provisioned. The staged deployment predates the authorization fix and remains dormant; deploy the corrected source and apply migration 0002 before any future activation. This is a real but dormant code deployment, not a live endpoint. A direct D1 integration check used a temporary reserved network ID and the exact Worker conditional UPSERT: initialization changed 1 row, stale initialization changed 0, valid advancement changed 1, competing stale advancement changed 0, readback confirmed sequence 2, and cleanup returned the test-row count to 0. This verifies D1 SQL behavior in a sequential test only; it does not prove concurrent multi-region operation, signed Worker request execution, rollback resistance, or independent administration. The Worker must not be exposed until secrets, trust-root fingerprint, access controls, independent operator review, and runtime verification are complete. The README contains the operator provisioning sequence.

**Still external:** production anchor signing-key ceremony and independently distributed fingerprint; independent GOD policy-key pin ceremony; signer/policy configuration; secret provisioning; redeployment of the corrected Worker and migration 0002; live protected endpoint; independent administration; concurrent-writer, rollback/restore, and outage evidence; and proof that anchor state cannot be rolled back with the validator host.

## Gate 3 — GAIA-JUSTICE policy and evidence providers

**Software delivered:** HTTPSJusticeProviders supplies two distinct, independently pinned SignedHTTPSDecisionClient instances. The existing JusticeEvidenceVerifier continues to require both policy and evidence decisions to be exactly True.

Each provider signs a response bound to the exact request digest, signer identity, request nonce, and a short validity window. The client rejects a shared signer ID, shared Ed25519 key, or shared HTTPS endpoint between the policy and evidence providers. The policy provider must independently retrieve the policy/audit material. The evidence provider must independently retrieve the evidence root, transition, accounting, and challenge-state material. A digest-shaped string alone is never evidence.

**Deployment requirements:**
1. Deploy separate policy and evidence authorities with distinct signing keys, distinct HTTPS endpoints, and independent operational ownership.
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


## Runtime composition example

The following shows the software wiring only. The endpoint URLs, public keys, signer IDs, and certificate paths must come from the independently administered production services; do not substitute test keys or guessed endpoints.

~~~python
from src.consensus.runtime import build_consensus_runtime
from src.governance.remote_providers import (
    GODHTTPSGate,
    HTTPSJusticeProviders,
    HTTPSSequenceAnchor,
    SignedHTTPSDecisionClient,
)

god_client = SignedHTTPSDecisionClient(
    GOD_DECISION_URL,
    signer_id=GOD_SIGNER_ID,
    trusted_public_key=GOD_PUBLIC_KEY,
)
anchor = HTTPSSequenceAnchor(
    SEQUENCE_ANCHOR_URL,
    signer_id=ANCHOR_SIGNER_ID,
    trusted_public_key=ANCHOR_PUBLIC_KEY,
    write_token=os.environ["CRYPTIC_SEQUENCE_ANCHOR_TOKEN"],
)
justice = HTTPSJusticeProviders(
    policy=SignedHTTPSDecisionClient(
        JUSTICE_POLICY_URL,
        signer_id=JUSTICE_POLICY_SIGNER_ID,
        trusted_public_key=JUSTICE_POLICY_PUBLIC_KEY,
    ),
    evidence=SignedHTTPSDecisionClient(
        JUSTICE_EVIDENCE_URL,
        signer_id=JUSTICE_EVIDENCE_SIGNER_ID,
        trusted_public_key=JUSTICE_EVIDENCE_PUBLIC_KEY,
    ),
)

runtime = build_consensus_runtime(
    network_id=NETWORK_ID,
    epoch=VALIDATOR_EPOCH,
    validators=AUTHENTICATED_VALIDATOR_SET,
    data_dir=PRIVATE_RUNTIME_DATA_DIR,
    god_trust_root_path=GOD_ROOT_PIN_FILE,
    god_signer_id=GOD_SIGNER_ID,
    god_trust_root_fingerprint=GOD_ROOT_FINGERPRINT_FROM_INDEPENDENT_CHANNEL,
    sequence_anchor=anchor,
    god_gate=GODHTTPSGate(god_client),
    policy_evidence_verifier=justice.verify_policy,
    justice_evidence_verifier=justice.verify_evidence,
    consensus_endpoint=CONSENSUS_ENDPOINT,
    require_external_anchor=True,
)
~~~

Validator proposal/vote signing is a separate call path. Construct HTTPSHSMEd25519Signer with the approved HSM endpoint, mTLS client certificate/private key, key ID, and independently pinned validator public key. Pass that signer to make_proposal_with_signer() and make_vote_with_signer(). The consensus process receives signatures and public keys, not raw validator private-key bytes.
