# CRYPTIC Hybrid Provenance — v1

## Purpose

The hybrid provenance model separates authoritative work evidence from its
portable representation. The receipt remains the source of truth. A portable
trophy manifest references that receipt and carries a deterministic integrity
digest so it can be transported and independently audited.

## Layers

1. **Receipt** — the authoritative record produced by the existing receipt
   module. It contains the 80-byte header, nonce, digest, target, ruleset,
   governance window, timestamp, and local verification result.
2. **Portable manifest** — a deterministic summary bound to the receipt ID.
   It does not replace or modify the receipt.
3. **Independent audit** — recomputes manifest integrity and verifies the
   manifest against the original receipt.

## Identity and hashing

The work_id and trophy_id values are domain-separated SHA-256 identifiers
derived from the receipt ID. receipt_hash is the receipt's canonical
receipt_id. manifest_hash is SHA-256 over canonical UTF-8 JSON with sorted
keys, compact separators, and the integrity.manifest_hash field omitted.

The manifest is deterministic for a given receipt. Its hash is an integrity
checksum, not a digital signature and not proof of issuer identity.

## Verification contract

A verifier must:
- verify the original receipt using verify_receipt;
- recompute the manifest hash;
- reconstruct the expected manifest from the supplied receipt;
- require exact equality, rejecting extra fields and altered metadata.

A manifest without its original receipt can be checked for internal hash
consistency, but cannot establish the underlying proof's validity. The full
audit_manifest_file operation therefore requires the authoritative receipt.

## Status boundaries

The v1 manifest always records network_acceptance: not_claimed. Local proof
verification is not network acceptance. No network status is inferred from
the existence of a receipt or manifest.

asset_type: proof_trophy classifies the record's purpose. Transferability is
left undefined, and valuation is null. These fields do not create a financial
instrument, token, wallet balance, or market value.

## File behavior

export_manifest writes canonical JSON and refuses to overwrite an existing
path. The file is created with owner-only permissions where supported.
audit_manifest_file(path, receipt) reads the exported record and verifies
its complete binding to the supplied receipt.

## Governing invariants

- **Boundary** — Nothing executes beyond its time.
- **Capacity** — Nothing claims capacity without measurement.
- **Correctness** — Nothing claims correctness without verification.

## Scope

This module is a local provenance and verification component. It does not
mine, submit work, contact pools, issue or transfer tokens, or interact with
payment services.
