# CRYPTIC v1.7 — Raw Observation Journal

## Purpose

The raw observation journal captures validated source pages before downstream
normalization. It preserves source payload fields and creates an ordered
SHA-256 hash chain so later audits can detect edits, deletion of interior
records, reordering, truncation, and broken append history.

## Record contract

Each JSONL record contains:

- Schema and contiguous sequence number.
- Source ID, source kind, and source schema.
- Source observation timestamp (metadata, not trusted time).
- Original page items and item count.
- A digest of the opaque next-page cursor, not the cursor itself.
- A deterministic observation ID.
- Previous record digest and current record digest.

Canonical JSON uses sorted keys, compact separators, UTF-8, and rejects
non-finite numbers and non-JSON payload values. Each line is newline-terminated.
The default maximum record size is 8 MiB.

## Append and concurrency

`append_page(path, descriptor, page)` validates the registered source
descriptor and page contract, verifies the existing journal from genesis,
then appends one record under an operating-system file lock. The record is
written with append semantics, flushed with `fsync`, and created with
owner-only permissions where supported.

The lock serializes cooperating processes using this journal path. It does not
protect against a process that deliberately ignores the lock or an administrator
who can rewrite the file. A damaged journal is never silently repaired;
append fails closed until the source of corruption is investigated.

Repeated observations are preserved as separate events. They share an
observation ID when their source, schema, timestamp, and payload match, but
their sequence and chain digests differ.

## Audit and retrieval

- `audit_journal(path)` validates every record, canonical encoding, sequence,
  observation ID, previous digest, and record digest.
- `read_records(path)` returns records only after a successful full audit.
- The audit root is the last record digest, or the all-zero genesis value for
  an empty journal.

Export or independently pin the audit root if it must be compared across
devices. The journal's internal hash chain alone does not authenticate who
created the file or establish a trusted timestamp.

## Privacy and security boundaries

- Provider cursors are not stored; only their SHA-256 digest is retained.
- Endpoint URLs and credentials are not copied into observation records.
- The journal does not store credentials, issue network requests, or mutate
  source systems.
- File mode 0600 is applied where supported; directory and filesystem policy
  remain deployment responsibilities.
- Hash chaining is tamper-evident, not WORM storage or protection from a
  privileged attacker who can rewrite all records and recompute the chain.
- The append operation re-verifies the full journal before each write; this
  favors correctness for the initial bounded implementation over high-volume
  append throughput. A separately verified index/checkpoint is a future scale
  optimization.

## Scope

This increment is the raw-capture foundation for Phase 2. It does not yet
implement streaming backpressure, normalization, cross-source discrepancy
analysis, replay orchestration, or provider-specific pagination.
