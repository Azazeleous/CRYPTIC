# GCF/1 — Protocol Decision Record

Status: **DECIDED FOR GCF/1 — IMPLEMENTATION/CONFORMANCE GATES APPLY**

## Decision 1 — No nil-vote in GCF/1

GCF/1 does not define a nil candidate, nil PREVOTE, or nil PRECOMMIT. The existing approve boolean remains a candidate-specific affirmative/negative vote:
- approve=true is an affirmative vote for the exact signed proposal candidate.
- approve=false is a negative vote for that exact candidate. It is not a nil vote and cannot contribute to a POLC or finality quorum.
- Absence of a vote is not a vote.
- A timeout, empty proposal, missing proposal, or round-change message must never be encoded as approve=false for a fabricated candidate.
- POLC remains a strict >2/3 certificate of affirmative PREVOTEs for one exact candidate.
- Finality remains based on the existing strict weighted affirmative PREVOTE/PRECOMMIT rules.

A future nil-vote feature requires a new versioned schema/domain (GCF/2 or an explicitly versioned extension), distinct vote_kind values (CANDIDATE/NIL), canonical signing bytes, updated vote aggregation and certificates, Worker verification, signer policy, migration rules, and cross-language conformance vectors. It must not reinterpret historical GCF/1 signatures.

Rationale: adding nil semantics by overloading a boolean would create wire ambiguity and could silently change quorum meaning for already signed messages.

## Decision 1A — GCF/2 explicit nil-vote profile (implementation in progress)

GCF/1 remains immutable and continues to use its candidate-specific `approve` boolean. GCF/2 introduces a separately versioned vote envelope and signature domain:

- `schema = GCF/2` and signature domain `GCF/2|VOTE|ED25519\\x00`.
- `vote_kind = CANDIDATE` carries a 32-byte `candidate_digest` and boolean `approve`.
- `vote_kind = NIL` carries `candidate_digest = null`, `approve = null`, and `polc_digest = null`. It is bound to network, epoch, height, round, parent hash, phase, validator, and a bounded signed validity window.
- Candidate PREVOTE must not carry a POLC. Affirmative candidate PRECOMMIT must carry a POLC digest. NIL PREVOTE and NIL PRECOMMIT never carry a POLC.
- NIL votes are counted in a separate nil-weight bucket. They never add to a candidate's affirmative PREVOTE/PRECOMMIT quorum, never form a POLC, never appear as candidate finality signers, and never create a candidate lock.
- A validator may cast only one vote per (network, epoch, height, round, phase) slot. A persistent anti-equivocation record is required even for NIL votes; "no candidate lock" does not mean "no signing history".
- Candidate votes remain subject to the existing proof-bound cross-round lock transition rule. NIL votes do not release or override any prior candidate lock.
- GCF/2 has a distinct signature domain; GCF/1 signatures are never reinterpreted as GCF/2.

The initial GCF/2 vote primitive binds a candidate vote to the digest of the existing signed proposal format. This is an interoperability bridge only: GCF/1 finality certificates do not accept GCF/2 votes. A GCF/2 finality certificate, engine admission path, persistent vote-slot storage, independent Python verifier, peer transport negotiation, Cloudflare Worker verifier, signer policy, and cross-language known-answer vectors are required before GCF/2 can be enabled or used for finality.

## Decision 2 — Round-change is a pacemaker signal, not a lock-release proof

A local timeout may cause a validator to construct and submit one signed ROUND_CHANGE message for a strictly higher target round. It does not:
- release a PREVOTE or PRECOMMIT lock;
- authorize a conflicting proposal or vote;
- count as a POLC;
- establish finality;
- permit erasing signing history.

A validator with no verified higher-round POLC remains bound by its durable local vote admission guard. The round-change certificate supplies evidence for proposal admission, while the local signer independently enforces the transition rule.

## Decision 3 — Timeout schedule

The production profile uses a bounded local pacemaker:
- Initial round timeout: 5 seconds.
- Backoff: exponential by round, min(5 * 2^round, 60) seconds, with saturating integer arithmetic.
- Maximum round timeout: 60 seconds.
- Proposal acceptance window is governed by signed proposal expiry and verifier clock-skew policy, not by the pacemaker timeout.
- Timeout is measured with a monotonic clock. Wall-clock timestamps are used only for signed message validity windows and audit records.
- No randomized jitter is included in consensus data or signed messages. Implementations may add bounded local scheduling jitter to avoid synchronized network bursts, but it must not alter target round or proof validation.
- A timeout creates a local scheduling event only. A ROUND_CHANGE signature is emitted only after the local persistent signer has durably recorded the exact signing intent and verified the local highest-POLC invariant.
- If the signer, storage, clock, or validator-set state is unavailable, the pacemaker fails closed and does not sign.

The pacemaker is not a consensus oracle. It does not automatically create proposals, select payloads, or bypass the proposal/justice/HCCGN gates.

## Decision 4 — Round progression

- Round numbers are monotonically increasing within a height.
- A validator may request target round R only when R is greater than its last durably recorded target/source round.
- Round-change certificates require strict >2/3 active-set weight and one message per validator.
- The proposal for round R>0 embeds the verified certificate for exactly R.
- A conflicting value requires a valid POLC whose round is strictly greater than every conflicting local lock round and strictly less than R.
- No certificate or quorum is synthesized from timeout events or local observations.
- If no valid certificate can be assembled, the node remains in its current safety state and reports liveness degradation.

## Decision 5 — Height and epoch boundaries

- A height advances only after independently verified finality and durable state/anchor commit.
- A process restart, host replacement, key rotation, or network partition does not advance height or epoch.
- Validator-set changes require the 3-of-4 HCCGN root-custodian governance ceremony defined in the operator model, with an explicit activation height and prior-set digest.
- Emergency key rotation creates a new epoch and requires a separately approved recovery manifest. It does not rewrite old signatures or finality records.

## Decision 6 — Compatibility

These decisions do not claim that a pacemaker or nil-vote implementation has already passed conformance tests. The current implementation supports proof-bound explicit round changes; automatic scheduling remains disabled until a separately tested controller is integrated. The protocol remains GCF/1 and does not reinterpret prior signed data.


## GCF/2 implementation status — durable vote slots and POLC (in progress)

The opt-in `GCF2VoteStore` now adds:

- Durable SQLite vote slots keyed by network, epoch, height, round, phase, and validator. Candidate and NIL votes compete for the same slot; a second or conflicting vote is rejected after restart as well as within one process.
- A trusted active-parent resolver is mandatory for both NIL and CANDIDATE votes. Candidate proposals must also resolve to the active parent at admission time; the parent hash carried by a signed vote is not trusted by itself.
- NIL votes consume the durable slot but do not create a candidate lock, erase an existing candidate lock, or contribute to candidate POLC weight.
- Candidate locks are durable per height and phase. A candidate change in a later round is allowed only when the new proposal carries a verified round-change certificate for exactly that target round and a highest POLC strictly above the prior lock whose stable value digest matches the new proposal. Same-round equivocation and round regression remain rejected.
- GCF/1 and GCF/2 vote stores must share the same SQLite database. Both submission paths reject a height/phase/validator slot already used by the other protocol version, preventing cross-version double-signing.
- An affirmative candidate PREVOTE quorum produces a deterministic GCF/2 POLC using the separate `GCF/2|POLC` domain and validator-ID-sorted signed PREVOTEs. An affirmative candidate PRECOMMIT is admitted only when it carries the exact persisted POLC digest.

This is still not a GCF/2 finality implementation. The store is opt-in and is not composed into the production runtime. No GCF/2 finality certificate, height advancement, signer/HSM policy integration, peer negotiation, Worker verification, cross-language vectors, or proof-bound lock transition is claimed. GCF/1 remains the only active finality profile. CI for the latest implementation is pending.


## GCF/2 implementation status — POLC, finality certificate, and runtime gate

The opt-in GCF/2 path now includes durable vote-slot admission and deterministic POLC construction as described above, plus:

- A durable GCF/2 finality-certificate record scoped uniquely to network, epoch, and height. The certificate contains the verified POLC and canonical validator-ID-sorted affirmative PRECOMMITs.
- An independent verifier checks the GCF/1 proposal signature and candidate context, GCF/2 vote signatures and windows, validator-set digest, POLC digest/quorum, PRECOMMIT digest binding/quorum, and finality-certificate digest.
- Once a GCF/2 finality certificate is stored, later votes at that height are rejected so additional arrivals cannot mutate the certificate or create a second finality value.
- GCF/1 and GCF/2 finality paths reject a conflicting certificate for the same network/epoch/height when they share the same database.
- The runtime exposes an explicit enable_gcf2_vote_store option. It is disabled by default and requires an injected trusted active-parent resolver. It is not exposed through the GCF/1 HTTP API.

**Activation boundary:** GCF/2 finality certificates, proof-bound cross-round candidate-lock transitions, signed peer HELLO negotiation, the persistent cross-version signer guard, Cloudflare Worker anchor verification, and the shared Python/JavaScript known-answer vector are implemented and CI-verified. The vote store remains disabled by default. The signer guard is an injected Ed25519 provider boundary, not evidence of deployed HSM custody or HSM-side anti-equivocation. GCF/2 is not yet wired into the autonomous GCF policy-update coordinator; finality/anchor operations require an explicitly configured caller. External validator and justice trust checks remain separate and mandatory.


## Pool boundary — work acceptance versus reward settlement

The current pool slice durably issues signed short-lived jobs from an injected active-target policy, authenticates workers through a trusted transport adapter (including pinned mTLS certificate mapping), independently verifies HCCGN submissions, reserves non-overlapping nonce intervals, and records accepted shares in a hash-chained append-only ledger. Jobs have durable active/revoked/expired lifecycle states; worker submission rate limits and measured worker share totals are persisted. An exact retry of previously committed work is acknowledged only when the share ledger chain verifies.

The finalized-block settlement ledger is now implemented. It requires an independently verified finality certificate, a pinned-key signed reward policy scoped to network/pool/epoch/height, a verified historical job, and one exact accepted proof matching the finalized proposal. It records only internal nonredeemable credits under an append-only hash chain and policy cap. The present job target remains the active network target; there is no separate pool share target or difficulty-weighted partial-share allocation. There is no transfer, withdrawal, redemption, payout rail, public operator API, or multi-coordinator failover. Accepted shares alone never mint credits.


## GCF/2 integration update — transport, signer guard, and certificate portability

GCF/2 finality certificates now embed the exact signed GCF/1 proposal, so the candidate digest and proposal signature can be independently checked from the certificate itself. The independent Python verifier verifies the embedded proposal, GCF/2 POLC, affirmative PRECOMMIT set, weighted quorums, and finality digest. The GCF/2 anchor envelope carries the same proposal and certificate; the Cloudflare Worker requires the envelope proposal to be byte-canonically identical to the proposal committed by the certificate and recomputes the GCF/2 certificate digest including that proposal.

The peer transport now has a signed, replay-protected capability HELLO. Peers negotiate GCF/1 or GCF/2 against their local enabled capabilities; GCF/2 vote messages are rejected until GCF/2 is negotiated and a GCF/2 vote store is configured. GCF/1 proposal/vote/round-change dispatch remains unchanged.

A persistent `ConsensusSigningGuard` is available to the runtime through an injected signing provider. It reserves a logical height/phase/validator slot across GCF versions before calling the provider, verifies the returned Ed25519 signature against the pinned validator public key, and only permits an exact payload retry. This is a signer adapter boundary, not proof of deployed HSM custody or independent HSM anti-equivocation enforcement.

A shared deterministic GCF/2 known-answer vector now exercises proposal signature, validator-set hash, candidate digest, vote signatures, POLC digest, and finality certificate digest in Python and JavaScript. CI evidence is required before marking the vector conformance gate complete.

**Still not production-activated:** HSM custody and hardware anti-equivocation evidence, multi-host peer deployment and partition/restart drills, independent justice authority evidence, independently administered validator hosts, and finality/anchor recovery drills. Proof-bound cross-round candidate-lock transitions are now implemented in the opt-in GCF/2 store: a conflicting value requires a verified round-change certificate whose highest POLC is from a round above the prior lock and commits to the new value. The Python independent verifier and Worker verify the proposal's round-change evidence; conformance tests are pending CI. GCF/2 remains opt-in.


## Verification update — 2026-11-23

PR #33 head `1708a6d57d87e64e4da51b749427a53ed3c75704` passed CRYPTIC CI (45159184507), mining-engine tests (45159184530), production-gate contracts (45159184429), and GAIA local trophy mining (45159184527). GCF/2 remains opt-in; passing conformance tests do not establish production deployment or independent key custody.


## Verification update — 2026-11-23

PR #33 head `61149ffb1b1936d99d81b377b6887e83f096abe2` passed CRYPTIC CI (45159423674), mining-engine tests (45159423603), production-gate contracts (45159423608), and GAIA local trophy mining (45159423842). GCF/2 remains opt-in; these tests do not establish production HSM custody or multi-host deployment.
