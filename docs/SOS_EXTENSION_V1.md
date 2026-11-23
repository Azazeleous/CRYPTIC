# CRYPTIC SOS and Extension Admission v1

## Scope

This phase adds a fail-closed, declarative extension admission boundary and an operator-visible virtual computer:

1. Signed extension manifests with publisher-key pinning and artifact SHA-256 binding.
2. Signed, short-lived capability grants restricted to the capabilities requested by the manifest.
3. Explicit virtual-path scopes for each grant.
4. A SQLite-backed, per-extension virtual filesystem with path traversal rejection and bounded file/count/total-byte quotas.
5. A fixed command interpreter with no shell parsing or arbitrary extension execution.
6. A transactional SHA-256-linked audit ledger and grant revocation.

## Extension admission

src/extensions/manifest.py verifies CRYPTIC-EXTENSION/1 manifests. The signature domain is CRYPTIC-EXTENSION-MANIFEST/1\\0. The publisher identity must resolve to a separately provisioned Ed25519 public key. The artifact bytes must match the manifest's SHA-256 digest. The manifest schema is exact, capability names are allowlisted, and the validity window is bounded.

Artifacts are stored as opaque bytes. This implementation never imports, evals, execs, unpacks, or launches extension code. A signed manifest is admission metadata, not permission to execute code.

## Capability grants

src/sos/virtual_computer.py verifies CRYPTIC-SOS-CAPABILITY-GRANT/1 records under CRYPTIC-SOS-CAPABILITY-GRANT/1\\0. A grant is bound to one installed extension, one signer, a short expiry, a nonce, a sorted capability subset, and explicit virtual-path scopes. It cannot grant capabilities the extension did not request.

Grant revocation is persisted and checked on every command. Unknown signers, invalid signatures, expired grants, revoked grants, path traversal, and out-of-scope access fail closed.

## Virtual computer

The virtual filesystem is stored in SQLite and namespaced by extension ID. It does not expose the host filesystem. Paths must be relative and cannot contain .., empty segments, backslashes, or NUL bytes. Per-file, per-extension byte, and file-count quotas are enforced.

The command interface accepts an argument vector, not a shell string. Its built-in command allowlist is:

- help
- pwd
- ls <virtual-directory>
- cat <virtual-path>
- write <virtual-path> <text>
- sha256 <virtual-path>
- rm <virtual-path>

Each command requires process.invoke; filesystem commands also require their matching filesystem capability and a resource scope. No pipes, substitutions, shell builtins, subprocesses, network, BLE, or home-automation actions are exposed.

The command budget is checked before transaction commit. The commands are bounded trusted host operations, but this is a cooperative budget, not a hard process-kill boundary. True OS process isolation, cgroups/job objects, memory/CPU enforcement, and a supervised worker process remain open.

## Audit and recovery

Every install, grant, revocation, and command result is recorded in one SQLite audit chain. The audit event and virtual filesystem mutation commit in the same transaction. The chain uses a domain-separated SHA-256 digest and links each event to the previous event hash. Appends verify the existing chain first; tampering blocks subsequent writes.

SQLite WAL and synchronous=FULL provide application-level transaction and recovery behavior. They do not establish WORM storage, independent replication, filesystem/controller-cache behavior, or physical power-loss durability.

## Verification

tests/test_sos_virtual_computer.py covers publisher signature verification, artifact substitution, manifest mutation, untrusted publishers, capability subset enforcement, resource scopes, traversal rejection, virtual file operations, command allowlisting, grant revocation, cooperative budget rollback, and audit tampering.

tests/test_gate_contracts.py also covers a trust-root parsing edge case: raw 32-byte Ed25519 keys are preserved exactly even when the first or last byte is an ASCII whitespace value.

CI evidence is recorded in the pull request and capability ledger only after the current branch head passes. No live extension code, host process isolation, device enrollment, or hardware durability is claimed.
