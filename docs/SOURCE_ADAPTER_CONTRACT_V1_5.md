# CRYPTIC v1.5 — Read-only Source Registry and Adapter Contract

## Purpose

This increment implements the first Phase 1 roadmap deliverable: a local
registry for explicitly supplied, read-only source adapters. It establishes
metadata, health, bounded-page, schema, and provenance boundaries before any
provider-specific connector is introduced.

## Adapter contract

An adapter exposes:

- an immutable `SourceDescriptor`;
- `health_check() -> HealthReport`;
- `fetch_page(limit, cursor, filters) -> SourcePage`.

The descriptor records a stable source ID, source kind, endpoint, auth mode,
declared requests-per-minute limit, maximum page size, pagination mode,
schema ID, enabled state, and a mandatory read-only flag.

The registry rejects embedded endpoint credentials, URL query strings,
unsupported schemes, invalid identifiers, duplicate IDs, write-capable
descriptors, malformed health reports, mismatched source/schema IDs, and
pages larger than the requested limit. Credential-like filter keys are
rejected before dispatch.

## Bounded pagination

- `none`: cursors are rejected.
- `cursor`: cursors are opaque strings bounded to 4096 characters.
- `offset`: cursors are non-negative 64-bit integer strings.

Every request has a caller-supplied positive limit no greater than the
registered source's `max_page_size`. The registry validates returned page
size and schema identity.

## Health and failure behavior

Health reports carry source ID, boolean health, observation timestamp,
optional latency, and a short reason. Adapter exceptions are converted to a
sanitized unhealthy report; raw exception text is not returned.

Page retrieval errors are wrapped as `SourceAdapterError`. The registry
does not silently retry, advance cursors, or discard conflicting observations.

## Security and implementation boundaries

- This registry is in-memory and local; it does not persist source enrollment.
- Registration does not create credentials or perform OAuth enrollment.
- The registry does not itself open sockets or implement provider transports.
- `rate_limit_per_minute` is declared adapter policy metadata; adapters must
  enforce it. A shared scheduler/throttler is a later integration.
- Endpoint credentials must be supplied through a separate protected provider,
  never embedded in URLs or committed configuration.
- Read-only is an explicit adapter contract; it is not a substitute for
  provider-side least-privilege credentials.

## API

Import from `src.ingestion`:

- `SourceDescriptor`
- `HealthReport`
- `SourcePage`
- `SourceAdapter`
- `SourceRegistry`

## Verification

The associated unit suite covers deterministic listing, duplicate rejection,
read-only enforcement, endpoint credential rejection, sanitized health
failures, page-size bounds, source/schema matching, credential-like filter
rejection, offset bounds, and explicit unregister behavior.

This is a local adapter contract, not evidence that any external provider is
connected, authenticated, available, or fully covered.
