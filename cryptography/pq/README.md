# CRYPTIC PQ Provider Boundary

This directory defines the integration boundary for post-quantum cryptography. It intentionally contains no home-grown cryptographic primitives.

Required provider operations:
- ML-KEM-768 key generation, encapsulation, and decapsulation;
- ML-DSA-65 key generation, signing, and verification;
- optional SLH-DSA signing and verification;
- public-key encoding/decoding with strict parameter-set identification;
- provider self-tests and standardized known-answer test vectors.

The provider adapter must expose explicit algorithm identifiers, reject parameter-set substitution, validate input lengths, avoid secret-bearing exceptions/logs, and surface provider/version metadata for the capability ledger.

No production status is assigned until a vetted provider is selected, dependency/license review is complete, official test vectors pass, and four-lane interoperability and key-lifecycle tests pass.

See docs/POST_QUANTUM_CRYPTOGRAPHY.md and docs/CRYPTOGRAPHIC_KEY_LIFECYCLE.md.
