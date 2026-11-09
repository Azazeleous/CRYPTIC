# Canonical Data Model

## SourceObservation
- observation_id
- source_id
- source_kind
- retrieved_at
- source_timestamp
- schema_id
- payload_digest
- payload_reference
- verification_status
- confidence_evidence
- discrepancy_ids

## AssetIdentity
- namespace
- chain_id
- contract_address or native_asset_key
- provider_aliases
- decimals
- symbol (display metadata, not identity)
- first_seen_at

## Market
- market_id
- venue_id
- base_asset_id
- quote_asset_id
- market_type
- status
- source_observation_id

## Device
- device_id
- public_key_fingerprint
- enrollment_state
- granted_capabilities
- last_seen
- revocation_state

All timestamps are UTC internally. Decimal financial quantities must not be represented with binary floating-point where exact decimal arithmetic is required.
