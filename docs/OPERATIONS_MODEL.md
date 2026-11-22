# CRYPTIC GCF/1 — Operator Model and Responsibility Boundaries

Status: **DECIDED — OPERATOR IDENTITIES AND CUSTODY EVIDENCE REQUIRED BEFORE ACTIVATION**

## 1. Operating model

Production GCF/1 uses four validators operated by four independent operator organizations. One person, organization, cloud account, HSM tenancy, or administrative identity must not control more than one validator. The four validator identities are equal-weight in the initial profile. A quorum is three of four validators (strictly greater than two-thirds).

This is a deployment profile, not a claim that four operators currently exist. The repository must remain in ACTIVATION_DISABLED until each operator completes enrollment and evidence checks.

## 2. Roles

| Role | Count | Authority | Separation rule |
|---|---:|---|---|
| Validator operator | 4 | Operate one validator host, maintain its availability, submit signed votes through its own signer | One operator and one administrative domain per validator |
| HCCGN root custodian | 4 | Hold one root-signing share/key and approve validator-set trust-root changes | Distinct people and custody domains from validator operators |
| Justice policy authority | 2 | Independently approve policy digest and evidence digest for a GAIA-JUSTICE commitment | Different organizations; both signatures required |
| Release/security authority | 2 | Review release artifact, threat model, and activation evidence | Neither may unilaterally activate |
| Incident commander | 1 per incident | Coordinate pause, containment, evidence preservation, and recovery | Cannot sign consensus messages or change trust roots by role alone |
| Auditor/witness | 1 per ceremony | Verify custody, enrollment, restore, and power-loss evidence | Must not be the operator whose evidence is being witnessed |

A role may be held by a real person only where the separation rules are satisfied. Automated service accounts are not independent human authorities.

## 3. Governance thresholds

- HCCGN trust-root and validator-set changes: 3-of-4 root-custodian approval over a canonical change manifest. The manifest includes network ID, epoch, validator IDs, public keys, weights, activation height, prior-set digest, and expiry.
- GAIA-JUSTICE policy/evidence: both independent authorities must sign the same canonical commitment digest. One signature is insufficient.
- Production release: two independent release/security approvals plus all machine gates.
- Emergency pause: any validator operator may locally stop its own signer; any two release/security authorities may request a global pause. A pause never authorizes unlocking, key rotation, or finality rollback.
- Resume: requires incident closure, preserved evidence, a successful recovery drill, and two independent release/security approvals. Resume cannot override a failed trust or signer gate.

## 4. Validator enrollment

For each validator, collect and verify:
1. Legal operator identity and named on-call contacts in a private operations registry (never commit personal data or secrets to this repository).
2. Independent cloud/account ownership and billing/admin control evidence.
3. Host hardware identity, measured boot/attestation evidence where supported, OS image digest, and patch baseline.
4. Ed25519 consensus public key and HSM/KMS key identifier; private key material must never enter the repository, CI, D1, or application logs.
5. mTLS certificate fingerprint and validator ID binding.
6. Successful signer-policy negative tests and a witnessed restart/restore test.
7. A signed operator acceptance of this runbook and incident responsibilities.

Reject enrollment if two validators share an administrative owner, signing key, HSM tenancy, or a single failure domain that can disable or control both.

## 5. Separation of duties

- Validator hosts do not administer the trust root.
- Root custodians do not operate validator signing services.
- Justice authorities do not operate validator nodes or control the HCCGN root.
- CI identities can test and deploy dormant software but cannot mint production consensus keys, trust roots, justice approvals, or anchor write credentials.
- Cloudflare Worker credentials are separate from validator keys and cannot sign consensus messages.
- No operator may use another operator's credentials for availability recovery.

## 6. Incident and evidence handling

Every incident receives a unique incident ID and append-only evidence bundle containing UTC timestamps, affected validator IDs, software/image digests, relevant signed messages, anchor sequence/hash, and operator actions. Preserve original logs and signatures; do not rewrite history. A recovery action that changes keys or validator membership creates a new governance epoch and requires the trust-root ceremony.

## 7. Current completion state

The repository can define and enforce role boundaries, but cannot create independent organizations, prove legal identity, attest physical custody, or witness a real power-loss campaign. Those evidence items remain external activation gates. No synthetic operator identities or simulated attestations may be recorded as production evidence.
