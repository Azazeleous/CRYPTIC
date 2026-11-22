# CRYPTIC Production Gate Runbook v1

This runbook distinguishes deployable software from external authority and hardware evidence. GCF proposal admission now uses the configured validator set as its local governance policy; GCF finality still requires its existing strict greater-than-two-thirds weighted PREVOTE and PRECOMMIT quorums. The repository does not manufacture trust-root pins, validator keys, policy evidence, or durability claims.

## Upstream G.O.D. repository boundary

The public `machackabook/G.O.D.` repository is G.O.D. v5.0.1: a browser capability detector, explicit-consent gate, optional read-only Chrome companion, and local evidence-receipt interface. Its published architecture explicitly places a future authenticated SYNAPSE gateway outside that repository. It is **not** the authoritative GOD governance policy service, trust-root issuer, or signed decision endpoint; CRYPTIC's current proposal-admission and sequence-anchor paths do not depend on that browser application or a separate GOD transition-signing endpoint. The cross-repository interface and evidence map is documented at [G.O.D. — CRYPTIC production-gate integration](https://github.com/machackabook/G.O.D./blob/main/docs/CRYPTIC-PRODUCTION-GATE-INTEGRATION.md).

Consequently, the public G.O.D. repository update documents the boundary only. CRYPTIC no longer requires that browser application or a separate GOD decision endpoint to admit GCF proposals: an eligible proposer must be a member of the configured network/epoch validator set and must present the exact public key registered for that validator. The existing GCF weighted PREVOTE/PRECOMMIT quorums remain the finality authority. Gate 2 now verifies the resulting GCF finality certificate against a separately pinned validator set before an anchor transition.


## Gate 1 — HCCGN proof trust root and validator-set proposal policy

**Software delivered:** load_independently_pinned_root() validates the HCCGN proof-policy root-pin record against a fingerprint supplied through a separate trusted channel. GCF proposal admission uses ValidatorSetProposalAuthorizer: the proposer ID and public key must match the active network/epoch ValidatorSet. A separate GOD network round-trip is not required for proposal admission. Admission is not finality; the existing GCF PREVOTE and PRECOMMIT rules still require strictly more than two-thirds of configured voting weight.

**Deployment requirements:**
1. Provision the active validator set for the exact network and epoch. Validator IDs, public keys, and weights must be approved through the network's genesis/epoch governance process.
2. Ensure every proposer ID and public key exactly matches that active validator set. Unknown validators, wrong epochs, and key mismatches are denied.
3. Separately transfer the HCCGN proof-policy public key and SHA-256 fingerprint through two independent authenticated channels. Do not copy the fingerprint from the same file or repository as the key.
4. Provision the pin record:
   {"schema":"CRYPTIC-GOD-ROOT-PIN/1","signer_id":"<GOD signer id>","public_key_hex":"<64 lowercase hex chars>"}
5. Provision the independently obtained fingerprint to the verifier as expected_fingerprint.
6. Verify validator-set epoch activation, key matching, and weighted quorum behavior against the exact configured validator set.

**Still external:** HCCGN root authorization, out-of-band fingerprint ceremony, validator-set governance, root rotation/recovery approvals, and live validator key custody. Never replace them with a generated test key.

## Gate 2 — Independent monotonic sequence anchor

**Software delivered:** HTTPSSequenceAnchor submits a GCF/1 finality certificate with each sequence transition. The Cloudflare Worker independently verifies the signed proposal, candidate digest, pinned validator-set hash/network/epoch, proposer membership/key, unique PREVOTE and PRECOMMIT signatures, POLC digest, and strict greater-than-two-thirds voting weight in both phases. The transition is bound to the exact anchor tuple: proposal height equals the new sequence, proposal parent hash equals the expected old anchor hash, and proposal payload hash equals the new policy hash. A bearer token is transport authentication only and cannot authorize a transition.

The Worker requires an independently pinned validator-set configuration:
- `ANCHOR_VALIDATOR_SET_JSON`: sorted validator IDs, public keys, and weights with exact network and epoch.
- `ANCHOR_VALIDATOR_SET_SHA256`: expected SHA-256 of canonical `{network_id, epoch, validators}`.
- `ANCHOR_VALIDATOR_NETWORK_ID` and `ANCHOR_VALIDATOR_EPOCH`: exact active scope.
- `ANCHOR_SIGNING_KEY_PKCS8_B64`, `ANCHOR_SIGNER_ID`, and `ANCHOR_WRITE_TOKEN`: separate anchor signing and transport credentials.

A D1 receipt derived from the certificate digest rejects replay. The conditional D1 UPSERT remains the single atomic compare-and-swap point. Missing or inconsistent validator-set configuration returns HTTP 503; invalid certificate or signatures return HTTP 403; stale/replayed transitions return HTTP 412.

**Certificate contract:** the client passes the exact `GCFEngine.finalize(candidate_digest)["certificate"]` object to `HTTPSSequenceAnchor.advance_sequence(..., certificate=certificate)`. For HCCGN target-policy updates, call `HCCGNActiveTargetPolicy.digest_snapshot(snapshot)` first; create and finalize a GCF proposal whose `payload_hash` equals that policy digest, `anchor_sequence` equals the policy sequence, and `parent_hash` equals the current anchor hash; then call `install(snapshot, finality_certificate=certificate)`. The certificate must be for the same network/epoch, its anchor_sequence must equal the new anchor sequence, its proposal parent hash must equal the expected old anchor hash, and its proposal payload hash must equal the new policy hash. HCCGN policy installation now refuses to advance an external anchor without that certificate.

**Trust boundary:** a valid GCF finality certificate establishes that the pinned validator set finalized that exact proposal. It does not independently prove that the HCCGN proof is valid or that GAIA-JUSTICE policy/evidence checks passed. Those remain separate gates. Validator-set governance, public-key distribution, and live key custody must be independently administered; the Worker does not become GOD authority.

**Deployment requirements:** deploy the corrected Worker source and apply all D1 migrations, including `0003_gcf_finality_certificate_receipts.sql`; provision the validator-set configuration and independently obtained hash; create/provision the anchor signing key and write token through the approved secret manager; keep Workers.dev disabled and the route unpublished until independent review; then test certificate tampering, wrong network/epoch/set hash, duplicate signers, invalid signatures, insufficient PREVOTE/PRECOMMIT quorum, POLC mismatch, replay, concurrent CAS, stale writers, restore, and outage.

**Still external:** independently approved validator-set genesis/epoch governance and hash distribution; production anchor signing-key custody; secret provisioning; corrected Worker deployment; protected endpoint and independent administration; concurrent-writer, rollback/restore, and outage evidence; and proof that anchor state cannot be rolled back with the validator host.

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

CI contract tests verify GCF certificate signatures, pinned validator-set binding, POLC and weighted quorums, certificate replay rejection, anchor compare-and-swap semantics, remote signer output, mutual-TLS loopback transport, and ADAM process-crash recovery. They do not certify external services or production hardware.

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

For each `advance_sequence()` call, pass the exact certificate returned by `GCFEngine.finalize(candidate_digest)["certificate"]`. The client reads the signed anchor tuple and submits the certificate; the Worker independently verifies the certificate against its pinned validator set and exact old/new anchor binding before D1 mutation. If the anchor changes between read and write, the CAS fails. Validator proposal/vote signing is a separate call path. Construct HTTPSHSMEd25519Signer with the approved HSM endpoint, mTLS client certificate/private key, key ID, and independently pinned validator public key. Pass that signer to make_proposal_with_signer() and make_vote_with_signer(). The consensus process receives signatures and public keys, not raw validator private-key bytes.
