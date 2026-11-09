# Security Model

- Default-deny network, filesystem, process, and device access.
- Enroll devices using cryptographic identities; use short-lived, scoped credentials and revocation.
- Keep secrets outside source control and model context.
- Sandbox untrusted extensions with resource limits and restricted syscalls/network/filesystem.
- Require explicit grants for BLE, home automation, shell, mounts, and remote device actions.
- Sign and hash artifacts; verify signatures and provenance before loading.
- Audit administrative changes and sensitive actions.
- Apply dependency scanning, SBOM generation, secret scanning, and vulnerability response.
- Treat model-generated code, extension metadata, source responses, and retrieved documents as untrusted input.
- Provide backup, restore, incident response, and credential rotation procedures.

Owner identity is established by enrollment and cryptographic proof, not by a username string or model prompt.
