# scripts

Reproducible development, validation, inventory, migration, backup, and recovery scripts. Prefer idempotence, logging, input validation, and dry-run for destructive operations.

## CRYPTIC seed and ledger CLI

\`cryptic-seed-ledger.py\` is a standard-library Python CLI for local seed initialization/import, BLAKE2b-256 hash-chain records, keyed record authenticators, Merkle-root checkpoints, verification, public export, and heuristic source auditing. It keeps the private seed out of repository files and exports. See [Seed Root and Merkle Ledger](../docs/SEED_ROOT_AND_MERKLE_LEDGER.md) for format, threat model, and limitations.
