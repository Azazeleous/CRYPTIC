# CRYPTIC Provenance Federation v1

## Purpose

The federation layer combines independently stored local provenance archives
into one deterministic audit view. It rebuilds each source archive's
provenance index from its receipt wallet and trophy-manifest directory; it
does not trust a supplied index summary as source evidence.

A federation preserves source identity and every indexed occurrence. If the
same receipt appears in more than one archive, the federation reports the
cross-archive duplicate and retains each source occurrence rather than
silently collapsing it.

## Source configuration

Create a UTF-8 JSON file with one entry per archive:

```json
{
  "sources": [
    {
      "source_id": "galaxy-a15",
      "wallet_file": "/path/to/device-a/receipts.jsonl",
      "manifest_dir": "/path/to/device-a/trophies"
    },
    {
      "source_id": "hp-aio",
      "wallet_file": "/path/to/device-b/receipts.jsonl",
      "manifest_dir": "/path/to/device-b/trophies",
      "expected_archive_root": "64-character-lowercase-sha256-from-owner"
    }
  ]
}
```

Each `source_id` must be unique and non-empty. Paths are read as local input
and are deliberately excluded from the federation output so the same archive
set can be audited from different mount locations.

`expected_archive_root` is optional. When provided, the federation rebuilds
the source index and compares the observed archive root with the supplied
checkpoint. A mismatch is an explicit issue; it is never silently accepted.

## CLI

Build and print the federation:

```sh
python -m src.mining.provenance_federation --sources federation-sources.json
```

Export a clean federation to a new file:

```sh
python -m src.mining.provenance_federation --sources federation-sources.json --output federation.json
```

Rebuild and audit an existing export against all source archives:

```sh
python -m src.mining.provenance_federation --sources federation-sources.json --verify federation.json
```

Export uses exclusive file creation and refuses to overwrite an existing
destination. A federation with source issues, checkpoint mismatches, or
cross-archive duplicates is not exportable as a clean federation.

## Output and verification

The output contains:

- source checkpoints rebuilt independently through `build_index`;
- source-specific status, indexed-record count, issue count, and archive root;
- all indexed receipt occurrences, annotated with their source ID;
- cross-archive duplicate receipt IDs and the complete list of source IDs;
- source archive issues and expected-checkpoint mismatches;
- a deterministic SHA-256 federation root over canonical source checkpoints,
  records, and issues.

`verify_federation` rebuilds the entire federation from source archives and
requires exact equality. The export's federation root is an integrity
checkpoint, not a digital signature.

## Trust boundaries

- Receipt and manifest verification remain delegated to the existing local
  provenance index.
- The federation does not upgrade local proof verification into external
  network acceptance.
- Cross-archive duplicate receipt IDs are reported, not deduplicated away.
- SHA-256 checkpoints detect content changes; they do not authenticate an
  issuer or prove who supplied a checkpoint.
- Signed attestations and key-trust policy are intentionally not implemented
  in v1. They require a separately specified issuer identity and key
  distribution model.
- Network acceptance, valuation, transferability, and payment semantics are
  outside this local provenance system.

## Governing invariants

**Boundary** — Nothing executes beyond its time.

**Capacity** — Nothing claims capacity without measurement.

**Correctness** — Nothing claims correctness without verification.
