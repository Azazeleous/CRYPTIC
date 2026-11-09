# Device Assistant Model

Device access is capability-based and opt-in.

Enrollment binds a device public key to a device record. Each bridge declares supported operations, required scopes, data collected, resource limits, and revocation behavior.

Initial protocol families:
- HTTPS and WebSocket
- SSH (explicit host enrollment and user authorization)
- ADB (developer-authorized devices only)
- BLE GATT (service/characteristic allowlists)
- MQTT and documented home-automation APIs
- Local filesystem and process APIs inside the SOS boundary

No universal direct access is assumed. Device-specific protocols, pairing, permissions, and operating-system restrictions remain authoritative.
