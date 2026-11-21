# GCF / ADAM / APEX Integration Record

**Repository:** Azazeleous/CRYPTIC  
**Baseline:** main `b4545cd5fc506d6b68148fefaf53687040da0b62`  
**Working branch:** `feat/apex-reference-gcf-adam`  
**Status:** source audit complete; network integration not yet implemented

## 1. Existing CRYPTIC miner

The current tree contains:

- `src/mining/sha256d.py`: bounded 80-byte SHA-256d scanner, optimized and reference kernels, finite nonce ranges, adaptive chunk sizing, multiprocessing, and independent candidate verification.
- `src/mining/gaia_fabric.py`: arithmetic routing metadata, disjoint four-lane range plan, coprime traversal, and graph diagnostics.
- `src/mining/trophy_solver.py`: local challenge ladder, L1/L3 computation, L2/L4 candidate re-verification, receipt creation, and portable trophy manifests.
- `src/mining/receipt_wallet.py`, `trophy_manifest.py`, and `wallet_trophy_archive.py`: local evidence persistence and audit.
- `tests/test_sha256d_miner.py` and `tests/test_gaia_instant_solver.py`: deterministic scanner, lane, receipt, and manifest tests.

The current miner is explicitly a **local proof-trophy solver**. It does not submit HCCGN work, participate in GCF consensus, or claim network acceptance. Its local 80-byte trophy header is not automatically an HCCGN block header.

The existing `mining-engine-tests` and `gaia-local-trophy-mining` workflows passed on the commit whose tree is now on main. The workflow verifies the local 13-tier trophy ladder; this is not network-finality evidence.

## 2. GOD policy source and boundary

The operational GOD network gate is in:

- `machackabook/Sovereign-Operating-System/bridge/god_network_gate.py`
- `machackabook/Sovereign-Operating-System/docs/GOLDEN-ARMY-FORGE-GOD.md`

Its documented scope is outbound network requests routed through Golden Army Forge. It is not a global firewall, router policy, device attestation service, or consensus engine.

Relevant behavior:

- Local compute has a fast path.
- External capabilities are deny-by-default.
- The private policy file is external to the public repository.
- The currently executable network capability is public GitHub metadata GET.
- Device attestation is denied when no trusted verifier is connected.
- A policy decision is not itself evidence that a remote operation executed.

Therefore GCF proposal/vote submission must not silently bypass GOD. The current GOD capability allowlist does not contain an HCCGN/GCF submission capability. Network submission remains denied until an operator-authorized GOD policy and executor explicitly support it.

## 3. ADAM and APEX source boundary

CRYPTIC already has `src/mining/root_of_trust.py` and `docs/CRYPTIC_ROOT_OF_TRUST_V1_3.md`. These implement pinned-root Ed25519 verification for signed policy snapshots and root rotation, with anti-rollback inputs supplied by the caller. They do not provide an ADAM state-commit database or a consensus finality engine.

The imported `HELENA_APEX_SOVEREIGN_CORE_v127.html` is retained under `docs/reference/` with source provenance. It is a visual HTML console. Its terminal commands return local display messages and placeholder acknowledgements; it is not an APEX proof validator or ADAM commitment service.

The ADAM matrix HTML artifact found in the source repository is likewise a visualization, not evidence of a working state-transition commit engine.

## 4. GCF/1 protocol baseline

The previously discussed GCF/1 design calls for:

- JCS-canonical JSON wire envelopes.
- `POST /v1/consensus/proposals`.
- `POST /v1/consensus/votes`.
- Ed25519 proposer and validator signatures.
- Replay protection and persistent proposal/vote state.
- PREVOTE and PRECOMMIT rounds.
- Weighted quorum strictly greater than two-thirds of total voting weight.
- A finality certificate binding candidate, parent, validator-set identity, quorum evidence, and lock/PoLC evidence.

These are recovered design decisions, not existing CRYPTIC endpoints or code. The final wire schema, signature preimages, validator-set genesis, and full lock/equivocation rules must be encoded in tests before the protocol is treated as normative.

An HTTP 202/accepted response is not finality. A candidate becomes committed only after independent certificate verification and ADAM parent-state continuity checks.

## 5. Required acceptance pipeline

The intended boundary is:

1. **HCCGN work:** build the canonical network work header; compute the protocol-defined digest; evaluate the network target; independently reverify the candidate.
2. **GOD:** authorize the exact outbound capability and destination before any proposal/vote network operation. Local mining does not require a network round trip.
3. **GCF:** validate signed proposal, replay/round rules, validator set, prevote PoLC, precommit quorum, and finality certificate.
4. **APEX inside ADAM:** independently validate policy authority/activation, evidence integrity, HCCGN proof, justice receipt, GCF finality, and parent-state continuity.
5. **ADAM commit:** atomically persist only an APEX-approved finalized transition; preserve the receipt, policy digest, candidate digest, parent digest, validator-set digest, and commit height.

Candidate eligibility and finality are separate predicates:

`P_eligible = I ∧ H ∧ R ∧ G ∧ J ∧ T`

`P_final = P_eligible ∧ Q ∧ L`

Where I=identity, H=integrity, R=independently verified work, G=authorized policy, J=justice/evidence checks, T=time validity, Q=weighted quorum, and L=valid lock/PoLC evidence.

APEX cannot manufacture work proof, policy authority, quorum, or finality. ADAM cannot commit an unfinalized candidate.

## 6. First implementation targets

- `src/consensus/gcf_wire.py`: canonical envelope encoding, proposal/vote schemas, signature preimages, and strict field validation.
- `src/consensus/finality.py`: validator-set hashing, duplicate/equivocation checks, weighted prevote/precommit quorum, and certificate verification.
- `src/governance/god_adapter.py`: fail-closed adapter to the host GOD gate; no fallback allow path.
- `src/adam/apex_validator.py`: the ADAM-owned validation authority; no implicit acceptance when a verifier is missing.
- `src/adam/commit_store.py`: transactional, idempotent state commitment with parent/height continuity.
- `src/mining/hccgn_adapter.py`: exact HCCGN header/work binding to the existing scanner only after the canonical HCCGN header and digest rules are confirmed.

## 7. Blocking protocol input

The repository and currently attached project files establish the local SHA-256d trophy format, but do not establish the canonical HCCGN network work-header serialization and digest rule. The HCCGN adapter must not guess whether the network uses SHA-256, SHA-256d, another digest, or a different header layout.

Until that canonical work-header contract is fixed, local trophy candidates remain local evidence and cannot be represented as HCCGN network proofs.

## 8. Required tests before network acceptance

- Canonical serialization vectors and signature preimage vectors.
- Invalid proposer/validator signatures and wrong network/epoch/height/parent.
- Expired and future-dated proposals; replayed nonces and duplicate messages.
- Duplicate validator votes, equivocation, wrong phase/round/candidate, and validator-set mismatch.
- Quorum boundary tests at exactly two-thirds and strictly above two-thirds.
- Missing or invalid prevote PoLC; invalid precommit certificate.
- GOD missing-policy, malformed-policy, denied-capability, wrong-host, and attestation-required cases.
- Invalid/expired governance policy, policy sequence rollback, and root rotation.
- HCCGN header known-answer vectors, target boundaries, and independent candidate re-verification.
- Justice evidence missing/substituted/corrupt, deterministic replay mismatch, and value-accounting violations.
- ADAM wrong parent, duplicate commit, interrupted transaction, recovery, and historical immutability.

No network acceptance, production finality, or payout claim is valid until these tests and live integration evidence pass.
