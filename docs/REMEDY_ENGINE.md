# Remedy Engine

Remedy record fields: error_class, signature, preconditions, diagnosis, remedy_steps, risk_level, required_permissions, rollback, verification_tests, source_evidence, author, review_state.

Execution procedure:
1. Capture error and context.
2. Classify without discarding original details.
3. Match known remedies by exact signature and compatible preconditions.
4. Check policy, permissions, and blast radius.
5. Apply only an approved, bounded remedy.
6. Verify the original invariant independently.
7. Record result and evidence.
8. If no remedy matches, draft a proposed remedy, test it in isolation, and submit it for review.

Never hide an error by returning success or by retrying indefinitely.
