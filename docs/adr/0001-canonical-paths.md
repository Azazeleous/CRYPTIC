# ADR 0001: Canonical Endpoint Paths

Status: accepted

Public routes use the direct `/cryptic` prefix with no `/api` prefix and no version segment. Compatibility changes are handled through documented contracts and migration policy rather than versioned URL nesting.

Examples: `/cryptic/health`, `/cryptic/sources`, `/cryptic/assets`, `/cryptic/stream`.
