# GAIA / NEXUS Instant Trophy Solver

## Scope

The solver binds the existing CRYPTIC SHA-256d scanner to the GAIA arithmetic
fabric, four-lane execution plan, independent inverse-style verification,
receipt wallet, and portable trophy manifests.

This is a **local proof-trophy challenge**, not an HCCGN consensus miner, pool
client, or cryptocurrency payout system. Its receipts explicitly retain
network.status = not_submitted; portable manifests say
network_acceptance = not_claimed.

## Run

From the repository root:

    python -m src.mining.trophy_solver --challenge-id gaia-first-run --seed public-challenge-seed --max-difficulty 16 --workers 4

Or use the script entry point:

    python scripts/mine_gaia_trophies.py --challenge-id gaia-first-run --seed public-challenge-seed --max-difficulty 16 --workers 4

The default difficulty ladder is 4 through 16. The default confidence target is
99%. If no explicit attempt budget is supplied, the solver computes the exact
geometric-trial budget for the requested maximum difficulty and confidence.
Use --attempts N to impose a smaller or larger finite budget.

The SHA-256d target for difficulty d is:

    target(d) = (2**256 - 1) >> d

Since the target comparison is inclusive, exactly 2**(256-d) of the
2**256 possible digest values pass, giving a per-attempt probability of
2**(-d) under the uniform-digest model.

Expected trials are 2**d. The solver reports the exact geometric success
probability for the attempts actually scanned, Markov and Chebyshev upper
bounds, and the exponential geometric-tail bound. The spectral mixing
expression is explicitly labeled a scheduling heuristic until its eigenvalue
is verified for a particular transition operator.

## Four-lane binding

- L1: optimized forward SHA-256d computation over the first disjoint interval.
- L2: independent full-header recomputation of every L1 candidate.
- L3: reference SHA-256d computation over the second disjoint interval, with
  descending nonce traversal.
- L4: independent full-header recomputation of every L3 candidate.

The 97,152/28,160 and 1,518/440 arithmetic fabrics, modular stride/inverse,
799-step Cayley traversal, and V5 coordinate mapping provide deterministic
routing metadata and reversible ticket checks. They do not remove nonce
candidates or change the digest input. Every nonce in the requested interval
is assigned to exactly one compute lane.

The Schläfli {p/q} and discrete-divergence utilities are independent graph
diagnostics. A closed unit circulation has zero discrete divergence; winding
is not divergence. Hodge-star sign support is a parity identity helper, not a
claim that this module computes the full de Rham cohomology of a manifold.

## Trophy persistence

For each difficulty tier with a qualifying digest, the solver:

1. Independently verifies the candidate in its paired shadow lane.
2. Creates a CRYPTIC local proof-of-work receipt.
3. Appends the receipt to the local JSONL wallet.
4. Creates a portable trophy manifest bound to that receipt.
5. Writes the manifest without overwriting an existing file.

Defaults:

- Wallet: ~/.cryptic/trophies/wallet.jsonl
- Manifests: ~/.cryptic/trophies/manifests/

Audit the wallet:

    python -c "from src.mining.receipt_wallet import verify_wallet; import json; print(json.dumps(verify_wallet('~/.cryptic/trophies/wallet.jsonl'), indent=2))"

Reconcile the wallet and trophy archive:

    python -m src.mining.wallet_trophy_archive --wallet ~/.cryptic/trophies/wallet.jsonl --manifests ~/.cryptic/trophies/manifests

Trophies are local computational achievements. The manifest assigns no
monetary value and does not claim network acceptance.

## Verification

Run the complete test suite:

    python -m unittest discover -s tests -p 'test_*.py' -v

The integration tests cover the modulus/totient invariants, modular route
round-trips, 799 Cayley traversal, V5 coordinates, Schläfli traversal,
discrete divergence, difficulty bounds, disjoint lane ranges, reverse scanning,
four-lane shadow verification, receipt persistence, and portable manifest
creation.

## HCCGN adapter boundary

A separate HCCGN adapter must supply the authoritative header serialization,
work digest, target encoding, candidate predicate, parent/timestamp rules,
submission method, and independent acceptance evidence. The local trophy
challenge must never be substituted for those consensus rules.
