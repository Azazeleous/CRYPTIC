# CRYPTIC v1.9 — Deterministic Journal Replay and Data Quality

## Purpose

v1.9 replays a verified raw observation journal without network access or
journal mutation. It normalizes supported EVM/Solana records, preserves
normalization failures as explicit issues, and compares the latest observation
per source and network identity.

## Replay behavior

`replay_journal(path)` performs these steps:

1. Audit the complete raw journal and fail closed if its hash chain is invalid.
2. Read the journal again under its file lock and verify it has not changed.
3. Normalize each supported single-item chain observation.
4. Preserve every normalized historical observation in journal order.
5. Detect repeated observation IDs and per-source timestamp regressions.
6. Select the latest timestamped observation for each source/network pair.
7. Run the v1.8 cross-source discrepancy analysis.
8. Produce a deterministic replay digest over the complete report.

No source adapter is called, no network request is made, and the journal is not
modified.

## Quality semantics

The report separates validity from quality:

- `valid`: journal integrity passed and all records were understood by the
  supported normalizers.
- `quality_ok`: there are no normalization issues, duplicate-observation or
  timestamp-regression warnings, cross-source discrepancies, and at least one
  group has enough independent, time-aligned sources to compare.

A journal can be valid but not quality-clean. For example, a single source
can produce a valid normalized record but does not provide independent
cross-source evidence. A height lag or hash conflict is reported as a
discrepancy, not converted into a claim that a provider is dishonest.

## Data-quality records

- Unsupported or malformed source schemas are retained as normalization
  issues; they are never silently dropped.
- Duplicate observations remain in the replay history and are reported as
  warnings.
- Timestamp regressions are warnings based on source-provided metadata.
- Excessive observation skew is represented by the discrepancy engine as a
  skipped comparison group.
- Only the latest timestamped observation per source/network pair participates
  in cross-source comparison; all historical normalized records remain in the
  replay output.

## Determinism and limits

The report digest is reproducible for the same journal bytes and policy.
Source timestamps are not trusted time. Replay proves reproducibility of this
local transformation and the journal's internal hash chain; it does not prove
provider honesty, consensus correctness, external acceptance, or completeness
of the source data.

The replay output is currently returned in memory. Durable replay reports,
streaming backpressure, large-journal indexes, and incremental checkpoints are
future work.
