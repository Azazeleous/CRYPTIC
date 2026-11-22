# CRYPTIC Production Gate Runbook v1

## Current policy precedence

The current sequence-anchor authorization contract is the GCF/1 finality-certificate path described below. The earlier CRYPTIC-GOD-POLICY-TRANSITION/1 signed GOD transition proposal was an intermediate design and is superseded for anchor advancement; do not deploy or configure it as the current anchor authorization path. Proposal admission uses the active validator-set policy, while anchor mutation requires an independently verified GCF finality certificate bound to the exact old/new anchor tuple. This does not remove the independent HCCGN proof-root, GAIA-JUSTICE authority, validator key-custody, or physical durability gates. Any historical CI entry describing the GOD transition signer is implementation history, not current deployment instructions.

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

**Software delivered:** HTTPSSequenceAnchor submits a GCF/1 finality certificate with each sequence transition. The Cloudflare Worker independently verifies the signed proposal, candidate digest, pinned validator-set hash/network/epoch, proposer membership/key, unique PREVOTE and PRECOMMIT signatures, POLC digest, and strict greater-than-two-thirds voting weight in both phases. The transition is bound to the exact anchor tuple: proposal anchor_sequence equals the new sequence, proposal parent hash equals the expected old anchor hash, and proposal payload hash equals the new policy hash. A bearer token is transport authentication only and cannot authorize a transition.

The Worker requires an independently pinned validator-set configuration:
- `ANCHOR_VALIDATOR_SET_JSON`: sorted validator IDs, public keys, and weights with exact network and epoch.
- `ANCHOR_VALIDATOR_SET_SHA256`: expected SHA-256 of canonical `{network_id, epoch, validators}`.
- `ANCHOR_VALIDATOR_NETWORK_ID` and `ANCHOR_VALIDATOR_EPOCH`: exact active scope.
- `ANCHOR_SIGNING_KEY_PKCS8_B64`, `ANCHOR_SIGNER_ID`, and `ANCHOR_WRITE_TOKEN`: separate anchor signing and transport credentials.

A D1 receipt derived from the certificate digest rejects replay. The conditional D1 UPSERT remains the single atomic compare-and-swap point. Missing or inconsistent validator-set configuration returns HTTP 503; invalid certificate or signatures return HTTP 403; stale/replayed transitions return HTTP 412.

**Certificate contract:** the client passes the exact `GCFEngine.finalize(candidate_digest)["certificate"]` object to `HTTPSSequenceAnchor.advance_sequence(..., certificate=certificate)`. For HCCGN target-policy updates, call `HCCGNActiveTargetPolicy.digest_snapshot(snapshot)` first; create and finalize a GCF proposal whose `payload_hash` equals that policy digest, `anchor_sequence` equals the policy sequence, and `parent_hash` equals the current anchor hash; then call `install(snapshot, finality_certificate=certificate)`. The certificate must be for the same network/epoch, its anchor_sequence must equal the new anchor sequence, its proposal parent hash must equal the expected old anchor hash, and its proposal payload hash must equal the new policy hash. HCCGN policy installation now refuses to advance an external anchor without that certificate.

**Trust boundary:** a valid GCF finality certificate establishes that the pinned validator set finalized that exact proposal. It does not independently prove that the HCCGN proof is valid or that GAIA-JUSTICE policy/evidence checks passed. Those remain separate gates. Validator-set governance, public-key distribution, and live key custody must be independently administered; the Worker does not become GOD authority.

**Orchestrated policy-update path:** `GCFPolicyUpdateCoordinator` in `src/consensus/policy_update.py` is the composition layer for the complete transition. Configure `build_consensus_runtime(..., policy_update_proposer_id=..., policy_update_signer=...)` with the active validator's approved remote signer; the returned runtime exposes `runtime.policy_update`. Call `prepare(snapshot, proof_hash=..., justice_commitment=..., height=...)` to verify the signed HCCGN snapshot, read the shared mandatory anchor, bind its current hash and the next policy sequence into a signed GCF proposal, and submit it through the engine's normal HCCGN, active-validator-set proposal-admission, and GAIA-JUSTICE gates. Distribute the returned proposal to validators. They submit independently signed PREVOTEs and PRECOMMITs through the existing `POST /v1/consensus/votes` endpoint; PRECOMMITs must carry the computed POLC digest. After the GCF engine has accepted both strict weighted quorums, call `finalize_and_install(snapshot, candidate_digest=...)`. It obtains the engine-generated finality certificate, checks the policy/sequence/parent binding, passes the exact certificate to `HCCGNActiveTargetPolicy.install()`, and verifies the resulting anchor tuple. It never manufactures votes or substitutes a local success result for remote validator quorum.

The coordinator and target-policy registry must share the exact same configured sequence-anchor object, and external anchoring must be required. If quorum is absent, the coordinator does not mutate the policy or anchor. For direct-peer fan-out, configure a `GCFPeerMesh` from a local `GCFPeerNode`, a verified mTLS client context, and an explicit peer map of `host`, `port`, and `server_fingerprint`; pass it as `policy_update_peer_mesh` to the runtime. Use `await runtime.policy_update.prepare_and_broadcast(...)` to submit locally and fan out the signed proposal, then have each validator independently create and relay its own signed PREVOTE/PRECOMMIT with `await runtime.policy_update.broadcast_vote(vote)`. Each receiver validates the envelope sender, Ed25519 identity, TLS fingerprint, replay ID, and GCF vote before admitting it. Fan-out results report per-peer acceptance only; they do not represent quorum. This is configured direct-peer transport, not peer discovery or automatic gossip. The GCF HTTP API remains mounted behind authenticated TLS; do not expose its vote or proposal endpoints without the deployment's peer authentication and rate limits.

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
    HTTPSJusticeProviders,
    HTTPSSequenceAnchor,
    SignedHTTPSDecisionClient,
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
    god_gate=None,  # compatibility parameter; active ValidatorSet governs proposal admission
    policy_evidence_verifier=justice.verify_policy,
    justice_evidence_verifier=justice.verify_evidence,
    consensus_endpoint=CONSENSUS_ENDPOINT,
    require_external_anchor=True,
    policy_update_proposer_id=LOCAL_VALIDATOR_ID,
    policy_update_signer=LOCAL_VALIDATOR_HSM_SIGNER,
    policy_update_peer_mesh=CONFIGURED_GCF_PEER_MESH,
)
# The coordinator is available as runtime.policy_update.
# Use prepare(), distribute the proposal, collect signed peer votes,
# then call finalize_and_install() after both weighted quorums.
~~~

For policy changes, use the `runtime.policy_update` coordinator described in Gate 2; it ensures the proposal, finality certificate, and HCCGN install all refer to the same policy digest and anchor sequence. For direct anchor integrations, each `advance_sequence()` call must receive the exact certificate returned by `GCFEngine.finalize(candidate_digest)["certificate"]`. The client reads the signed anchor tuple and submits the certificate; the Worker independently verifies the certificate against its pinned validator set and exact old/new anchor binding before D1 mutation. If the anchor changes between read and write, the CAS fails. Validator proposal/vote signing is a separate call path. Construct HTTPSHSMEd25519Signer with the approved HSM endpoint, mTLS client certificate/private key, key ID, and independently pinned validator public key. Pass that signer to make_proposal_with_signer() and make_vote_with_signer(). The consensus process receives signatures and public keys, not raw validator private-key bytes.


## GCF/1 cross-round vote-lock safety boundary

The durable validator vote lock is scoped to (network_id, epoch, height, vote_type, validator_id), not to a round. A validator therefore cannot submit a different candidate for the same height and phase merely by incrementing the round number. PREVOTE and PRECOMMIT retain separate phase locks. The lock is committed in the same SQLite transaction as vote admission and is recovered from the persisted vote journal.

Existing databases using the earlier round-scoped primary key are migrated on startup. Before migration, the engine checks historical locks for a validator that voted for different candidate digests across rounds at the same height and phase. If such a conflict exists, initialization fails closed with PERSISTED_CROSS_ROUND_EQUIVOCATION; it does not select a winner or rewrite the history. Otherwise, the lock table is rebuilt with the height-scoped key while preserving the existing candidate lock.

**Liveness trade-off:** this conservative rule does not implement round-change unlocks. A validator locked to a candidate for a height/phase remains locked for that height/phase, even if the network later needs another round. A future round-change protocol must define and verify a signed unlock/locking certificate, safety-preserving POLC rules, timeout evidence, and restart recovery before relaxing this invariant. Do not clear locks manually or treat a timeout as authorization to vote for another candidate.

This is a local engine safety invariant, not evidence of a complete multi-validator round controller or live multi-host BFT operation. CI must exercise cross-round conflicts and legacy-database migration before the capability is promoted.


Verification on code commit 0ec655907a3f1a986ccd7c5c66f9efe525336a58:
- CRYPTIC CI run 45037739415 passed 398 tests (2 skipped).
- Production-gate contracts run 45037739458 passed on Ubuntu and Windows, including the cross-round vote-lock and SQLite migration cases.
- Mining-engine tests run 45037739237 passed.
- GAIA local trophy run 45037739324 passed.

The initial Windows run exposed only a test-fixture file-handle cleanup issue; both SQLite fixture connections are now explicitly closed, and the corrected Windows run passed.


## GCF/1 pre-sign vote lock at the remote signer boundary

The vote builder now requires PersistentGCFVoteSigner. This wrapper verifies that the HSM signer's public key is the active validator key, parses the exact canonical GCF/1 vote message, and atomically records a lock keyed by network, epoch, height, phase, and validator. The lock includes both the candidate digest and the full vote-message digest, so a changed round or changed vote body cannot be signed under the same height/phase. The SQLite WAL transaction uses synchronous=FULL and commits before the HSM request is sent. Only the identical message can be retried after an ambiguous signer timeout; a different message is rejected before another signing request.

HTTPSHSMEd25519Signer.sign() now rejects GCF vote-domain messages unless they pass through the durable wrapper, and make_vote_with_signer() rejects an unguarded signer. Proposal signing remains separate. This prevents accidental bypass through the standard vote-builder path.

**Trust boundary:** this is a local pre-sign guard, not a substitute for HSM-side authorization. If another process or operator can call the HSM endpoint directly, the HSM service must enforce the same per-validator height/phase lock before releasing a signature. The local lock database is consensus safety state: it must be on persistent protected storage and backed up and recovered under the operator's change-control process. SQLite WAL/synchronous=FULL is not physical power-loss certification; Gate 5 remains separate. No timeout-based lock clearing or round-change unlock is implemented.

**Enrollment and recovery rule:** the first creation of a vote-lock database requires an explicit one-time initialize=True enrollment action. Normal startup must leave the flag false. If the database is missing, empty, incomplete, bound to another validator/key, or bound to another validator-set hash, construction fails closed. Do not use initialize=True to recover a missing production database while reusing the same validator identity; restore the authenticated prior lock state or follow a separately approved validator identity/key rotation and re-enrollment process.

Verification on code commit 8db70bca3a68c8c3dc9678a041c6fbc876d52e74:
- CRYPTIC CI run 45038382615 passed 403 tests (2 skipped).
- Production-gate contracts run 45038382603 passed on Ubuntu and Windows.
- Mining-engine tests run 45038382641 passed.
- GAIA local trophy run 45038382668 passed.


## Real-socket GCF peer transport contract

`tests/test_peer_mesh.py` now includes a two-node loopback integration test using generated Ed25519 X.509 certificates, a test CA, mutual TLS client/server contexts, client-certificate fingerprint allowlisting, hostname verification, and the transport's length-prefixed signed envelope. It exercises a successful proposal dispatch and a repeated message-ID rejection by the receiver's persistent replay database. The certificates are test-only ephemeral fixtures and do not represent production PKI or validator key custody.

This closes the gap between the earlier fan-out test double and a real local TLS socket round trip. It remains a loopback integration test: it does not demonstrate independent hosts, internet routing, operator separation, certificate rotation/revocation, packet loss, partition recovery, or production key custody.

**Corrected-head verification on commit 78e6ef56e4d67c268d050c4bf34bd766ef25260e:**
- [CRYPTIC CI](https://github.com/Azazeleous/CRYPTIC/actions/runs/45043028097) passed 404 tests (2 skipped); the new real mutual-TLS test passed.
- [Production-gate contracts](https://github.com/Azazeleous/CRYPTIC/actions/runs/45043028122) passed on Ubuntu and Windows, including the mTLS peer interoperability contract.
- [Mining-engine tests](https://github.com/Azazeleous/CRYPTIC/actions/runs/45043028107) passed 404 tests (2 skipped).
- [GAIA local trophy](https://github.com/Azazeleous/CRYPTIC/actions/runs/45043028140) passed.


## Inbound peer resource bounds and stalled-client handling

GCFPeerNode now bounds concurrent inbound handlers (default 128; configurable range 1–1024), sets the listener backlog to that bound, and applies a bounded I/O timeout (default 10 seconds; configurable range 0.1–60 seconds) to TLS handshakes, frame reads, response writes, and connection close. A client that sends only a partial frame receives a PEER_IO_TIMEOUT rejection; it cannot hold an active handler indefinitely. The outbound GCFPeerMesh retains its separate bounded fan-out concurrency and per-peer timeout.

Corrected-head verification on code commit b143380bc6d2cc932a8b7fe79919798df0f0eea9:
- [CRYPTIC CI](https://github.com/Azazeleous/CRYPTIC/actions/runs/45043373731) passed 405 tests (2 skipped).
- [Production-gate contracts](https://github.com/Azazeleous/CRYPTIC/actions/runs/45043373733) passed on Ubuntu and Windows.
- [Mining-engine tests](https://github.com/Azazeleous/CRYPTIC/actions/runs/45043373684) passed 405 tests (2 skipped).
- [GAIA local trophy](https://github.com/Azazeleous/CRYPTIC/actions/runs/45043373701) passed.

This verifies resource bounds and timeout behavior in CI; it does not establish resistance to volumetric network denial-of-service or substitute for production ingress protections and host-level resource monitoring.


## GCF round-change status — design gate

The cross-round vote-lock rule remains enabled. There is no timeout-based unlock, no round-change certificate, and no complete round controller in the current implementation. See [GCF Round-Change Protocol](GCF_ROUND_CHANGE_PROTOCOL.md) for the proposed signed message, weighted certificate, POLC selection, local lock-transition, signer/HSM, Worker, persistence, migration, and adversarial-test requirements.

The design document is explicitly **design only**. It does not change the GCF/1 wire format, authorize a lock transition, or satisfy a production gate. The current engine's vote-admission locks and the remote signer's pre-sign locks are separate safety state and must both be addressed by any future implementation. A timeout is not proof of a safe lock change.

Do not mark round-change complete until the protocol has independent review, versioned schema/migrations, engine and signer integration, HSM-side enforcement, independent finality/Worker verification, adversarial restart/concurrency tests, and multi-host partition/recovery evidence.
