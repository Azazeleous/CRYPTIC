# Wallet-to-Trophy Archive Reconciliation — v1

## Purpose

The reconciliation utility reads an existing local JSONL receipt wallet and
creates one deterministic portable trophy manifest for each unique valid
receipt. The receipt remains authoritative; manifests are derived records.

## Operation

1. Read wallet JSONL records and preserve source line numbers.
2. Reject malformed JSON and receipts that fail independent receipt checks.
3. Deduplicate valid receipts by their 64-character receipt ID.
4. Create a manifest only when its deterministic destination does not exist.
5. Verify any existing manifest against its matching receipt; never overwrite it.
6. Report manifest files that do not correspond to a valid receipt in this wallet.

## Output

The returned reconciliation report contains:
- number of wallet records read;
- number of unique valid receipts;
- newly generated manifests;
- already-present verified manifests;
- duplicate receipt occurrences;
- invalid receipts and malformed line numbers;
- conflicting existing manifests;
- orphaned manifest files;
- an aggregate validity flag.

A conflict is not automatically repaired. The operator must preserve the
original file and investigate it separately. No historical receipt is
rewritten or deleted.

## Idempotency

Running reconciliation repeatedly against an unchanged wallet and output
directory creates no duplicate manifests. Existing files are verified rather
than overwritten.

## Scope and trust

The utility performs local file and provenance operations only. It does not
mine, submit work, contact a network, issue or transfer assets, or determine
external acceptance. A manifest hash is an integrity checksum, not a digital
signature or proof of issuer identity.
