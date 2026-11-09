# Verification and Evidence Policy

Every observation and capability records: identifier, source or implementation revision, timestamp, input digest, output digest, test method, result, and limitations.

## Evidence levels

- E0: idea or unverified assertion
- E1: documented design
- E2: implementation present
- E3: deterministic unit tests pass
- E4: integration tests pass against identified sources
- E5: security/recovery review completed
- E6: production behavior observed with operational evidence

## Data verification

Validate schema, source identity, timestamps, freshness, canonical identifiers, units, numeric ranges, duplicate handling, and cross-source discrepancies. Preserve conflicting observations; do not silently average or discard them.

## Model verification

Use held-out evaluation, task-specific metrics, calibration, regression suites, data lineage, model cards, and rollback. Training data must have documented provenance and lawful usage basis.
