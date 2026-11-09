# Sovereign Operating System (SOS) Design

SOS begins as an isolated virtual computer, not an unrestricted host shell.

Components:
- virtual machine/container runtime adapter
- virtual terminal and command broker
- virtual filesystem with explicit mount table
- process supervisor and resource quotas
- network namespace and egress policy
- artifact store and snapshots
- operator-visible console
- signed action/audit log

Host mounts are read-only by default. Writable mounts require an explicit scoped grant. Shell commands execute in the isolated environment with time, memory, CPU, and filesystem limits.
