# CRYPTIC Provenance Index v1

The provenance index is a deterministic local catalog connecting authoritative
proof receipts to their matching portable trophy manifests. It organizes
evidence; it does not manufacture validity or assert network acceptance.

## Six connected capabilities

1. **Stable receipt-to-trophy relationships** — each indexed row binds the
   receipt ID, derived work ID, trophy ID, and manifest hash.
2. **Verification evidence** — rows preserve the receipt and proof verification
   states supplied by a fully verified manifest. These are current local
   verification facts, not a fabricated historical event log.
3. **Duplicate and conflict detection** — malformed wallet lines, invalid
   receipts, duplicates, missing manifests, mismatched manifests, and orphan
   files are reported separately.
4. **Archive integrity checkpoint** — a SHA-256 root is computed over canonical
   JSON containing the sorted indexed records. It is a reproducible integrity
   checkpoint, not a digital signature or issuer authentication.
5. **Portable collection export** — the complete index can be exported as
   canonical JSON to a new file. Existing files are never overwritten.
6. **Reproducible audit** — the exported index is rebuilt from the wallet and
   manifest directory and compared exactly with the source-derived index.

## CLI

Build and print an index:

```bash
python -m src.mining.provenance_index --wallet ./wallet/receipts.jsonl --manifests ./wallet/trophies
```

Build and export a new collection index:

```bash
python -m src.mining.provenance_index --wallet ./wallet/receipts.jsonl --manifests ./wallet/trophies --output ./wallet/provenance-index.json
```

Audit an existing export against its source archive:

```bash
python -m src.mining.provenance_index --wallet ./wallet/receipts.jsonl --manifests ./wallet/trophies --verify ./wallet/provenance-index.json
```

Exit status is zero only when the report is valid. Export refuses to overwrite.

## Trust boundaries

- A record is indexed only after the receipt independently verifies and the
  corresponding manifest verifies exactly against that receipt.
- Local SHA-256d proof verification is not network acceptance.
- The index claims no token issuance, transfer, ownership registry, or value.
- The archive root detects changes relative to a rebuilt source index; it is
  not a signature and does not authenticate who created the archive.
- Historical verification chronology is not invented. This v1 records the
  current verification evidence present in the source artifacts.

## Reproducibility

No wall-clock build timestamp or machine-specific absolute path is included.
Given identical wallet records and manifest contents, the index bytes and
archive root are deterministic.
