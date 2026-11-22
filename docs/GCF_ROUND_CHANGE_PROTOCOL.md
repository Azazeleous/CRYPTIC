# GCF/1 Round-Change Protocol — Safety Specification

Status: **DESIGN ONLY — NOT IMPLEMENTED; NOT ENABLED**

This document specifies the work required before GCF may safely advance a height across rounds while allowing a validator to change a previously selected value. It does not add a round-change wire message, unlock a validator, change the vote signer, or alter finality verification. The existing cross-round locks remain authoritative.

## 1. Current implementation boundary

The current GCF engine persists a vote lock keyed by:

`(network_id, epoch, height, vote_type, validator_id)`

The round is retained as lock metadata, but is deliberately not part of the lock key. A validator that has voted for one candidate in a phase cannot vote for a different candidate in that phase at another round. Timeout, process restart, peer loss, or proposal expiry does not release this lock.

The remote `PersistentGCFVoteSigner` independently records a durable pre-sign intent keyed by network, epoch, height, phase, and validator. It binds both the candidate digest and the full signed-message digest. An ambiguous signer result permits only an identical-message retry.

These are conservative safety guards, not a complete round controller. The current GCF vote model also does not provide the complete Tendermint-style nil-vote/PoLC state machine. In particular, the current engine lock table is not equivalent to a consensus lock acquired only after a verified greater-than-two-thirds PREVOTE certificate. Do not reinterpret or clear existing rows as if they were POLC locks.

## 2. Protocol objective and invariants

A future implementation may advance from round (r) to round (R>r) only with an authenticated round-change certificate whose signer weight is strictly greater than two-thirds of the active validator-set weight.

The protocol must preserve all of these invariants:

1. **Height isolation:** every message and proof binds the exact network, epoch, and height.
2. **Round monotonicity:** a round-change certificate targets a round strictly greater than every included message's source round.
3. **Validator uniqueness:** at most one round-change message per validator is counted in one certificate.
4. **Signature authenticity:** every round-change message and every embedded vote is verified against the active validator-set key.
5. **Weighted quorum:** the certificate uses integer arithmetic and requires `floor(2*total_weight/3)+1`; equality to two-thirds is insufficient.
6. **Highest-lock preservation:** a proposal for a later round must carry the highest valid POLC reported by the certified round-change set. If that certificate contains a POLC, the proposal must use the value selected by the highest POLC.
7. **Local lock preservation:** a validator must not sign a conflicting PREVOTE merely because a timeout elapsed or a round-change certificate exists. It may change its local consensus lock only after validating a POLC at a strictly higher round than its recorded lock round.
8. **Separate signing history:** changing a consensus lock must never erase historical signed messages, signing intents, or equivocation evidence.
9. **Restart equivalence:** after restart, the validator must recover the same lock, highest valid POLC, and signed-message history before it can sign another vote.
10. **Finality unchanged:** a height finalizes only with the existing strict weighted PREVOTE/PRECOMMIT requirements and a certificate that independently verifies all proposal, vote, POLC, validator-set, and transition bindings.

## 3. Proposed message model

The following is a design target, not an accepted wire format.

### 3.1 Signed round-change message

A `GCF-ROUND-CHANGE/1` message should bind:

- schema;
- network_id and epoch;
- height;
- source_round and target_round;
- validator_id;
- issued_at and a bounded validity window;
- a unique nonce/message identifier;
- highest_polc, either null or a complete independently verifiable POLC object;
- signature over the canonical unsigned message under a dedicated domain separator.

The message must be rejected if its validator is not in the active set, the public key does not match, the network/epoch/height differs, the target round is not greater than the source round, the time window is invalid, the nonce is replayed, or the embedded POLC fails independent verification.

A signer must not be allowed to report a lower POLC than its durable local consensus lock. If local lock state says a valid POLC at round (q) exists, a signed round-change message for target round (R>q) must include that lock or a later valid POLC. This check belongs at the local signer boundary as well as in the consensus engine.

### 3.2 POLC proof

A POLC is a set of unique, valid, affirmative PREVOTE signatures for one exact candidate at one exact height and round, with total signer weight strictly greater than two-thirds.

The proof must bind:
- the exact candidate/proposal digest;
- network, epoch, height, and round;
- validator-set hash;
- canonical, validator-ID-sorted vote list;
- computed voting weight and required quorum weight.

Every embedded vote must be revalidated. A caller-supplied weight, a claimed boolean, or a digest without the underlying signed votes is not proof.

The current `_polc()` helper derives a POLC from votes stored locally for one candidate. A future implementation needs a reusable verifier that can validate an externally supplied proof without trusting a remote node's database or claimed weight.

### 3.3 Round-change certificate

A round-change certificate contains the exact target round and a canonical sorted list of unique signed round-change messages. The verifier must:

1. validate every message independently;
2. reject duplicate validator IDs and conflicting messages;
3. verify every embedded POLC;
4. compute weight from the active validator set, never from message fields;
5. require strict greater-than-two-thirds weight;
6. select the highest valid POLC round among the messages;
7. reject same-round conflicting POLCs rather than choosing one arbitrarily;
8. compute a domain-separated certificate digest over the canonical certificate.

The certificate must be bound to the new proposal. A proposal cannot cite a certificate for another network, epoch, height, or target round.

## 4. Proposal and lock-transition rules

A proposal in target round (R) must carry the verified round-change certificate and, when present, the highest POLC selected from it.

- If the certificate contains no POLC, the proposal may nominate a candidate, but each validator must still enforce its own persisted lock. A validator with a local lock must not vote for a different candidate.
- If the certificate contains a highest POLC for candidate (B) at round (q), where (q<R), the proposal must carry that exact proof and propose (B).
- A validator locked on candidate (A) at round (l) may change its lock to (B) only after verifying a POLC for (B) at (q>l), with (q<R), and verifying that the new proposal is bound to that proof.
- A validator that cannot prove the required transition must retain its existing lock and must not sign a conflicting affirmative PREVOTE.
- A timeout, missing peer, process restart, or higher round number is never a lock-transition proof.

The design must distinguish three records that the current implementation currently conflates or treats conservatively:

1. **Vote-signing history:** immutable record of every signed vote intent and signature, retained for equivocation/accountability.
2. **Consensus lock:** candidate and POLC round established by a verified lock-acquisition rule.
3. **Round-change state:** authenticated messages and certificates observed for the current height and target round.

Do not implement unlocking by deleting or overwriting the existing vote-lock rows.

## 5. Required schema and compatibility work

Before enabling the protocol, specify and review a versioned migration for:

- durable consensus-lock records including candidate digest, lock round, POLC digest, and validator-set hash;
- immutable signing-history records that retain every signed message digest and its exact round;
- persisted round-change messages and verified certificate digests;
- replay protection for round-change message identifiers;
- proposal fields that bind the round-change certificate and highest POLC;
- vote fields that unambiguously distinguish a candidate vote from a nil vote, if nil-vote progression is adopted.

The current `approve: bool` field is not a complete representation of Tendermint-style candidate-versus-nil voting. Do not overload `approve=false` as a nil vote without changing and reviewing the canonical schema, vote aggregation, POLC verification, finality certificate, Worker verifier, and signer policy together.

Migration must be atomic and fail closed. Existing rows do not contain sufficient information to infer a verified POLC-based lock. Preserve them as historical signing/vote locks; do not synthesize a consensus lock or infer an unlock permission from them. If the migration cannot prove a safe mapping, require an explicit operator-controlled recovery or validator identity/key rotation procedure.

## 6. Required integration points

A complete implementation is not complete until all of these components enforce the same transition rules:

- GCF proposal schema, canonical signing bytes, and proposal validation;
- GCF vote schema, canonical signing bytes, vote aggregation, and POLC verifier;
- engine lock acquisition, verified lock transition, and persistent recovery;
- `PersistentGCFVoteSigner` pre-sign policy and durable database migration;
- remote HSM/KMS signer authorization, so direct callers cannot bypass local lock policy;
- peer message schema, authenticated dispatch, replay persistence, and bounded resource handling;
- finality certificate schema and independent `verify_finality_certificate()`;
- Cloudflare sequence-anchor Worker verifier and its contract tests;
- HCCGN policy-update coordinator and proposal broadcast;
- capability ledger, runbook, and deployment gate evidence.

A Python-only lock transition is insufficient if the Worker or HSM still accepts a conflicting signature/certificate.

## 7. Adversarial verification matrix

The implementation must add tests for, at minimum:

- no round change with less than strict greater-than-two-thirds weight;
- exact two-thirds weight rejected;
- duplicate validator IDs rejected;
- unknown validator and wrong key rejected;
- wrong network, epoch, height, or target round rejected;
- target round equal to or below source round rejected;
- stale, future, expired, malformed, or replayed round-change messages rejected;
- malformed POLC, wrong candidate, wrong round, wrong validator-set hash, duplicate votes, invalid signatures, and insufficient POLC weight rejected;
- same-round conflicting POLCs fail closed;
- proposal that omits a required highest POLC rejected;
- proposal that cites a lower POLC when a higher one is certified rejected;
- proposal that changes candidate despite a certified highest POLC rejected;
- local signer refuses a conflicting vote without a valid higher-round POLC;
- local signer accepts only the exact safe lock transition and persists it before signing;
- direct HSM signing cannot bypass the transition policy;
- timeout alone never unlocks;
- crash between certificate verification, durable lock update, and signature request cannot produce an unsafe signature;
- restart restores lock and signing history exactly;
- concurrent round-change certificates cannot race the local lock state;
- old schema migration preserves all historical signed intents and fails closed on ambiguous state;
- no PREVOTE or PRECOMMIT quorum means no finality certificate;
- independent Worker verification rejects every malformed or insufficient round-change/POLC case;
- four independently operated nodes agree on the same lock transition under partition, delay, restart, and recovery drills.

Tests must include weighted validator sets, not only equal-weight fixtures, and Byzantine schedules that attempt to omit, equivocate about, or downgrade a previously reported POLC.

## 8. Rollout gates

1. Review the protocol and proof obligations independently before implementation.
2. Implement the canonical wire schema and pure verification functions first.
3. Add property-based and adversarial tests before any lock-release code exists.
4. Integrate engine persistence and local signer enforcement with crash/restart tests.
5. Add HSM-side enforcement and independent Worker certificate verification.
6. Run multi-process and multi-host partition/recovery drills with independent operators.
7. Keep the feature disabled until the complete integration and review evidence is recorded.

No step may mark the protocol production-ready based only on unit tests, loopback TLS, or CI.

## 9. Reference model

This design follows the safety-relevant structure of the Tendermint round-based model: later-round proposals carry the latest known proof-of-lock round; a validator changes a lock only when it has a valid proof from a later round; and a timeout advances the state machine but is not itself a lock-change proof.

References:
- Tendermint consensus state machine and POLC/lock rules: https://github.com/tendermint/tendermint/blob/main/spec/consensus/consensus.md
- Tendermint signing constraints and the distinction between signed-message history and consensus locking: https://docs.tendermint.com/master/spec/consensus/signing.html
- Safety/liveness discussion and lock-change rationale: https://docs.tendermint.com/master/spec/consensus/consensus.html

This is a reference model, not a claim that GCF is Tendermint-compatible or that importing these rules alone proves GCF safety. GCF must have its own complete, reviewed proof and cross-component implementation.

---

**Current operational rule:** GCF cross-round vote locks remain in force. No timeout-based unlock, round-change certificate, or automatic round advancement is implemented by this document.
