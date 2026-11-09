# API Contract

Canonical public prefix: `/cryptic`. No `/api` or version segment.

Initial routes:
- GET /cryptic/health
- GET /cryptic/sources
- GET /cryptic/sources/:id/health
- GET /cryptic/chains
- GET /cryptic/assets
- GET /cryptic/assets/:chain/:address
- GET /cryptic/markets
- GET /cryptic/quotes
- GET /cryptic/observations
- GET /cryptic/ingestion/runs
- GET /cryptic/verification
- WS /cryptic/stream

Contracts must define pagination, filters, rate limits, error envelope, idempotency, auth scopes, and schema compatibility. Route declarations alone are not implementation evidence.
