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
