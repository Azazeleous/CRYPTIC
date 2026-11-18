# Crystalline v1 schemas

These JSON Schemas define the public wire shapes for the first Crystalline admission contract.

## Files

- `candidate.schema.json` — immutable candidate identity, artifact digest, provenance, parent root, and requested capabilities.
- `adam-policy.schema.json` — versioned default-deny policy with capability rules and an Ed25519 signature envelope.
- `adam-decision.schema.json` — candidate- and policy-bound ALLOW, DENY, or QUARANTINE decision.
- `tdoc-transition.schema.json` — append-only state transition evidence.
- `checkpoint.schema.json` — signed Crystalline checkpoint with an explicit external-anchor reference.

## Validation

From the repository root:

```sh
python -m pip install "jsonschema>=4.23,<5"
python -m unittest tests.unit.test_crystalline_schemas -v
```

The CI workflow also runs the repository unit suite and Python compilation.

## Important boundaries

- JSON Schema validation checks structure; it does not verify cryptographic signatures, policy semantics, timestamp ordering, state-transition legality, or external-anchor truth.
- A validator must enable a format checker for `date-time` and `uri` formats.
- Signature verification must use a separately provisioned trust store and a maintained cryptographic library.
- The signature covers a deterministic canonical representation of the unsigned payload. The exact canonicalization and signature-envelope profile must be frozen before the signing implementation is released.
- The existing `cryptic-seed-ledger/v1` BLAKE2b-256 format remains unchanged. These schemas permit explicit SHA-256 and BLAKE2b-256 digest identifiers; they do not imply an automatic migration.

Schema files are contracts, not evidence that the corresponding runtime services have been implemented.
