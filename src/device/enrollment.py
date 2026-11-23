"""Signed device enrollment and challenge-response authentication.

This module defines identity, consent, scope, expiry, and revocation records.
It does not open network sockets or operate BLE/home-automation hardware.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

REQUEST_SCHEMA = "CRYPTIC-DEVICE-ENROLLMENT-REQUEST/1"
CERT_SCHEMA = "CRYPTIC-DEVICE-ENROLLMENT-CERT/1"
CHALLENGE_SCHEMA = "CRYPTIC-DEVICE-HOST-CHALLENGE/1"
RESPONSE_SCHEMA = "CRYPTIC-DEVICE-RESPONSE/1"
REVOCATION_SCHEMA = "CRYPTIC-DEVICE-REVOCATION/1"
REQUEST_DOMAIN = b"CRYPTIC-DEVICE-ENROLLMENT-REQUEST/1\x00"
CERT_DOMAIN = b"CRYPTIC-DEVICE-ENROLLMENT-CERT/1\x00"
CHALLENGE_DOMAIN = b"CRYPTIC-DEVICE-HOST-CHALLENGE/1\x00"
RESPONSE_DOMAIN = b"CRYPTIC-DEVICE-RESPONSE/1\x00"
AUDIT_DOMAIN = b"CRYPTIC-DEVICE-AUDIT/1\x00"
ZERO_HASH = "0" * 64
DEVICE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
HEX_32 = re.compile(r"^[0-9a-f]{32}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SIGNER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SCOPE = re.compile(r"^(network|ble|home|device):[A-Za-z0-9._:-]{1,128}$")
SUPPORTED_CAPABILITIES = frozenset({
    "device.status", "network.read", "ble.observe", "home.read",
})
MAX_REQUEST_TTL = 600
MAX_ENROLLMENT_TTL = 30 * 24 * 60 * 60
CHALLENGE_TTL = 120
SESSION_TTL = 15 * 60


class DeviceEnrollmentError(ValueError):
    """A device identity, consent, grant, or authentication failed validation."""


@dataclass(frozen=True)
class DeviceSession:
    session_id: str
    device_id: str
    capabilities: tuple[str, ...]
    scopes: tuple[str, ...]
    expires_at: int


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise DeviceEnrollmentError("canonical_encoding_failed") from exc


def _public_key(value: bytes | Ed25519PublicKey) -> Ed25519PublicKey:
    try:
        return value if isinstance(value, Ed25519PublicKey) else Ed25519PublicKey.from_public_bytes(value)
    except (TypeError, ValueError) as exc:
        raise DeviceEnrollmentError("ed25519_public_key_invalid") from exc


def _private_key(value: Ed25519PrivateKey | bytes) -> Ed25519PrivateKey:
    try:
        return value if isinstance(value, Ed25519PrivateKey) else Ed25519PrivateKey.from_private_bytes(value)
    except (TypeError, ValueError) as exc:
        raise DeviceEnrollmentError("ed25519_private_key_invalid") from exc


def _signature(key: Ed25519PrivateKey, domain: bytes, body: Mapping[str, Any]) -> str:
    return base64.b64encode(key.sign(domain + _canonical(body))).decode("ascii")


def _verify_signature(
    key: Ed25519PublicKey, signature_text: Any, domain: bytes,
    body: Mapping[str, Any], error_code: str,
) -> None:
    try:
        signature = base64.b64decode(signature_text, validate=True)
        if len(signature) != 64:
            raise ValueError("signature_length")
        key.verify(signature, domain + _canonical(body))
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise DeviceEnrollmentError(error_code) from exc


def _device_id(value: Any) -> str:
    if not isinstance(value, str) or not DEVICE_ID.fullmatch(value):
        raise DeviceEnrollmentError("device_id_invalid")
    return value


def _capabilities(values: Any, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, list) or (not values and not allow_empty):
        raise DeviceEnrollmentError("device_capabilities_invalid")
    if (any(not isinstance(value, str) or value not in SUPPORTED_CAPABILITIES for value in values)
            or values != sorted(set(values))):
        raise DeviceEnrollmentError("device_capabilities_invalid")
    return tuple(values)


def _scopes(values: Any, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, list) or (not values and not allow_empty) or len(values) > 128:
        raise DeviceEnrollmentError("device_scopes_invalid")
    if (any(not isinstance(value, str) or not SCOPE.fullmatch(value) or "*" in value for value in values)
            or values != sorted(set(values))):
        raise DeviceEnrollmentError("device_scopes_invalid")
    return tuple(values)


def _time_window(issued_at: Any, expires_at: Any, now: int, max_ttl: int, prefix: str) -> None:
    if (isinstance(issued_at, bool) or not isinstance(issued_at, int)
            or isinstance(expires_at, bool) or not isinstance(expires_at, int)
            or expires_at <= issued_at or expires_at - issued_at > max_ttl
            or issued_at > now + 30 or expires_at < now - 30):
        raise DeviceEnrollmentError(prefix + "_validity_invalid")


def make_enrollment_request(
    *,
    device_id: str,
    device_private_key: Ed25519PrivateKey | bytes,
    capabilities: Sequence[str],
    scopes: Sequence[str],
    issued_at: int,
    expires_at: int,
    consent: bool,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Create a device-signed request; explicit consent must be true."""
    if consent is not True:
        raise DeviceEnrollmentError("explicit_device_consent_required")
    private = _private_key(device_private_key)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    caps = _capabilities(list(capabilities))
    resource_scopes = _scopes(list(scopes))
    if (not isinstance(issued_at, int) or isinstance(issued_at, bool)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or expires_at <= issued_at or expires_at - issued_at > MAX_REQUEST_TTL):
        raise DeviceEnrollmentError("enrollment_request_validity_invalid")
    nonce_value = secrets.token_hex(16) if nonce is None else nonce
    if not isinstance(nonce_value, str) or not HEX_32.fullmatch(nonce_value):
        raise DeviceEnrollmentError("enrollment_request_nonce_invalid")
    body = {
        "schema": REQUEST_SCHEMA,
        "device_id": _device_id(device_id),
        "device_public_key_hex": public.hex(),
        "requested_capabilities": list(caps),
        "requested_scopes": list(resource_scopes),
        "consent": True,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce_value,
    }
    return {**body, "signature": _signature(private, REQUEST_DOMAIN, body)}


def make_enrollment_certificate(
    request: Mapping[str, Any],
    *,
    operator_private_key: Ed25519PrivateKey | bytes,
    signer_id: str,
    capabilities: Sequence[str],
    scopes: Sequence[str],
    issued_at: int,
    expires_at: int,
    enrollment_id: str | None = None,
) -> dict[str, Any]:
    """Operator-sign a reviewed subset of the device's explicit request."""
    if not isinstance(request, Mapping):
        raise DeviceEnrollmentError("enrollment_request_object_required")
    requested_caps = _capabilities(request.get("requested_capabilities"))
    requested_scopes = _scopes(request.get("requested_scopes"))
    caps = _capabilities(list(capabilities))
    resource_scopes = _scopes(list(scopes))
    if not set(caps).issubset(requested_caps) or not set(resource_scopes).issubset(requested_scopes):
        raise DeviceEnrollmentError("operator_certificate_exceeds_device_consent")
    if not isinstance(signer_id, str) or not SIGNER_ID.fullmatch(signer_id):
        raise DeviceEnrollmentError("operator_signer_id_invalid")
    identifier = secrets.token_hex(16) if enrollment_id is None else enrollment_id
    if not isinstance(identifier, str) or not HEX_32.fullmatch(identifier):
        raise DeviceEnrollmentError("enrollment_id_invalid")
    if (not isinstance(issued_at, int) or isinstance(issued_at, bool)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or expires_at <= issued_at or expires_at - issued_at > MAX_ENROLLMENT_TTL):
        raise DeviceEnrollmentError("enrollment_certificate_validity_invalid")
    body = {
        "schema": CERT_SCHEMA,
        "enrollment_id": identifier,
        "device_id": request.get("device_id"),
        "device_public_key_hex": request.get("device_public_key_hex"),
        "request_digest": hashlib.sha256(_canonical(dict(request))).hexdigest(),
        "signer_id": signer_id,
        "capabilities": list(caps),
        "scopes": list(resource_scopes),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    return {
        **body,
        "signature": _signature(
            _private_key(operator_private_key), CERT_DOMAIN, body
        ),
    }


def make_device_revocation(
    *,
    device_id: str,
    operator_private_key: Ed25519PrivateKey | bytes,
    signer_id: str,
    issued_at: int,
    expires_at: int,
    nonce: str | None = None,
) -> dict[str, Any]:
    if not isinstance(signer_id, str) or not SIGNER_ID.fullmatch(signer_id):
        raise DeviceEnrollmentError("operator_signer_id_invalid")
    if (not isinstance(issued_at, int) or isinstance(issued_at, bool)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or expires_at <= issued_at or expires_at - issued_at > 300):
        raise DeviceEnrollmentError("device_revocation_validity_invalid")
    nonce_value = secrets.token_hex(16) if nonce is None else nonce
    if not isinstance(nonce_value, str) or not HEX_32.fullmatch(nonce_value):
        raise DeviceEnrollmentError("device_revocation_nonce_invalid")
    body = {
        "schema": REVOCATION_SCHEMA,
        "device_id": _device_id(device_id),
        "signer_id": signer_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce_value,
    }
    return {
        **body,
        "signature": _signature(
            _private_key(operator_private_key), REVOCATION_DOMAIN, body
        ),
    }


def verify_host_challenge(
    challenge: Mapping[str, Any],
    host_public_key: bytes | Ed25519PublicKey,
    *,
    expected_signer_id: str,
    now: int,
) -> dict[str, Any]:
    if not isinstance(challenge, dict):
        raise DeviceEnrollmentError("host_challenge_object_required")
    fields = {
        "schema", "session_id", "device_id", "challenge", "host_signer_id",
        "issued_at", "expires_at", "signature",
    }
    if set(challenge) != fields or challenge["schema"] != CHALLENGE_SCHEMA:
        raise DeviceEnrollmentError("host_challenge_schema_invalid")
    if (not isinstance(challenge["session_id"], str) or not HEX_32.fullmatch(challenge["session_id"])
            or not isinstance(challenge["challenge"], str) or not HEX_32.fullmatch(challenge["challenge"])
            or challenge["host_signer_id"] != expected_signer_id):
        raise DeviceEnrollmentError("host_challenge_binding_invalid")
    _device_id(challenge["device_id"])
    _time_window(
        challenge["issued_at"], challenge["expires_at"], now,
        CHALLENGE_TTL, "host_challenge",
    )
    unsigned = {key: value for key, value in challenge.items() if key != "signature"}
    _verify_signature(
        _public_key(host_public_key), challenge["signature"],
        CHALLENGE_DOMAIN, unsigned, "host_challenge_signature_invalid",
    )
    return dict(challenge)


def make_device_response(
    challenge: Mapping[str, Any],
    *,
    device_private_key: Ed25519PrivateKey | bytes,
    host_public_key: bytes | Ed25519PublicKey,
    expected_host_signer_id: str,
    now: int,
) -> dict[str, Any]:
    verified = verify_host_challenge(
        challenge, host_public_key,
        expected_signer_id=expected_host_signer_id, now=now,
    )
    private = _private_key(device_private_key)
    body = {
        "schema": RESPONSE_SCHEMA,
        "session_id": verified["session_id"],
        "device_id": verified["device_id"],
        "challenge": verified["challenge"],
        "issued_at": now,
        "expires_at": verified["expires_at"],
    }
    return {
        **body,
        "signature": _signature(private, RESPONSE_DOMAIN, body),
    }


class DeviceRegistry:
    """Persistent enrollment, mutual-authentication sessions, and revocation."""

    def __init__(
        self,
        database: str | Path,
        *,
        operator_trust: Mapping[str, bytes | Ed25519PublicKey],
        host_signer_id: str,
        host_private_key: Ed25519PrivateKey | bytes,
        clock=time.time,
    ):
        if not isinstance(host_signer_id, str) or not SIGNER_ID.fullmatch(host_signer_id):
            raise DeviceEnrollmentError("host_signer_id_invalid")
        self.database = Path(database).expanduser()
        if self.database.exists() and self.database.is_symlink():
            raise DeviceEnrollmentError("device_database_symlink_forbidden")
        self.database.parent.mkdir(parents=True, exist_ok=True)
        if self.database.parent.is_symlink():
            raise DeviceEnrollmentError("device_database_parent_symlink_forbidden")
        self.operator_trust = dict(operator_trust)
        self.host_signer_id = host_signer_id
        self.host_private_key = _private_key(host_private_key)
        self.host_public_key = self.host_private_key.public_key()
        self.clock = clock
        with closing(self._connect()) as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    public_key_hex TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    enrollment_id TEXT NOT NULL UNIQUE,
                    request_nonce TEXT NOT NULL UNIQUE,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    enrolled_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending_sessions (
                    session_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL REFERENCES devices(device_id),
                    challenge_json TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS active_sessions (
                    session_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL REFERENCES devices(device_id),
                    capabilities_json TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS revocation_nonces (
                    nonce TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    signer_id TEXT NOT NULL,
                    issued_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _verify_audit(connection: sqlite3.Connection) -> bool:
        previous = ZERO_HASH
        expected = 1
        rows = connection.execute(
            "SELECT sequence,event_json,previous_hash,event_hash FROM audit_events ORDER BY sequence"
        ).fetchall()
        for sequence, event_json, previous_hash, event_hash in rows:
            try:
                event = json.loads(event_json)
                if not isinstance(event, dict):
                    return False
                encoded = _canonical(event)
                digest = hashlib.sha256(
                    AUDIT_DOMAIN + bytes.fromhex(previous) + encoded
                ).hexdigest()
            except (ValueError, TypeError, json.JSONDecodeError):
                return False
            if (sequence != expected or event.get("sequence") != sequence
                    or encoded.decode("utf-8") != event_json
                    or previous_hash != previous or event_hash != digest):
                return False
            previous = digest
            expected += 1
        return True

    @classmethod
    def _audit(
        cls, connection: sqlite3.Connection, *, actor: str, action: str,
        resource: str, outcome: str, details: Mapping[str, Any] | None, timestamp: int,
    ) -> None:
        if not cls._verify_audit(connection):
            raise DeviceEnrollmentError("device_audit_chain_integrity_failure")
        last = connection.execute(
            "SELECT sequence,event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if last is None else last[0] + 1
        previous = ZERO_HASH if last is None else last[1]
        event = {
            "sequence": sequence, "timestamp": timestamp, "actor": actor,
            "action": action, "resource": resource, "outcome": outcome,
            "details": dict(details or {}),
        }
        encoded = _canonical(event)
        digest = hashlib.sha256(
            AUDIT_DOMAIN + bytes.fromhex(previous) + encoded
        ).hexdigest()
        connection.execute(
            "INSERT INTO audit_events(sequence,event_json,previous_hash,event_hash) VALUES(?,?,?,?)",
            (sequence, encoded.decode("utf-8"), previous, digest),
        )

    def enroll(
        self, request: Mapping[str, Any], certificate: Mapping[str, Any],
    ) -> str:
        if not isinstance(request, dict) or not isinstance(certificate, dict):
            raise DeviceEnrollmentError("enrollment_documents_required")
        request_fields = {
            "schema", "device_id", "device_public_key_hex", "requested_capabilities",
            "requested_scopes", "consent", "issued_at", "expires_at", "nonce", "signature",
        }
        if set(request) != request_fields or request["schema"] != REQUEST_SCHEMA:
            raise DeviceEnrollmentError("enrollment_request_schema_invalid")
        device_id = _device_id(request["device_id"])
        if request["consent"] is not True:
            raise DeviceEnrollmentError("explicit_device_consent_required")
        public_hex = request["device_public_key_hex"]
        if not isinstance(public_hex, str) or not HEX_64.fullmatch(public_hex):
            raise DeviceEnrollmentError("device_public_key_hex_invalid")
        device_public = _public_key(bytes.fromhex(public_hex))
        requested_caps = _capabilities(request["requested_capabilities"])
        requested_scopes = _scopes(request["requested_scopes"])
        now = int(self.clock())
        _time_window(request["issued_at"], request["expires_at"], now, MAX_REQUEST_TTL, "enrollment_request")
        nonce = request["nonce"]
        if not isinstance(nonce, str) or not HEX_32.fullmatch(nonce):
            raise DeviceEnrollmentError("enrollment_request_nonce_invalid")
        request_unsigned = {key: value for key, value in request.items() if key != "signature"}
        _verify_signature(
            device_public, request["signature"], REQUEST_DOMAIN,
            request_unsigned, "device_request_signature_invalid",
        )

        cert_fields = {
            "schema", "enrollment_id", "device_id", "device_public_key_hex",
            "request_digest", "signer_id", "capabilities", "scopes",
            "issued_at", "expires_at", "signature",
        }
        if set(certificate) != cert_fields or certificate["schema"] != CERT_SCHEMA:
            raise DeviceEnrollmentError("enrollment_certificate_schema_invalid")
        if (certificate["device_id"] != device_id
                or certificate["device_public_key_hex"] != public_hex
                or certificate["request_digest"] != hashlib.sha256(_canonical(request)).hexdigest()):
            raise DeviceEnrollmentError("enrollment_certificate_request_binding_invalid")
        enrollment_id = certificate["enrollment_id"]
        signer_id = certificate["signer_id"]
        if not isinstance(enrollment_id, str) or not HEX_32.fullmatch(enrollment_id):
            raise DeviceEnrollmentError("enrollment_id_invalid")
        if not isinstance(signer_id, str) or not SIGNER_ID.fullmatch(signer_id):
            raise DeviceEnrollmentError("operator_signer_id_invalid")
        caps = _capabilities(certificate["capabilities"])
        scopes = _scopes(certificate["scopes"])
        if not set(caps).issubset(requested_caps) or not set(scopes).issubset(requested_scopes):
            raise DeviceEnrollmentError("operator_certificate_exceeds_device_consent")
        _time_window(
            certificate["issued_at"], certificate["expires_at"], now,
            MAX_ENROLLMENT_TTL, "enrollment_certificate",
        )
        try:
            operator_key = _public_key(self.operator_trust[signer_id])
        except (KeyError, TypeError) as exc:
            raise DeviceEnrollmentError("operator_signer_untrusted") from exc
        cert_unsigned = {key: value for key, value in certificate.items() if key != "signature"}
        _verify_signature(
            operator_key, certificate["signature"], CERT_DOMAIN,
            cert_unsigned, "enrollment_certificate_signature_invalid",
        )
        timestamp = now
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO devices(device_id,public_key_hex,capabilities_json,scopes_json,enrollment_id,request_nonce,expires_at,enrolled_at) VALUES(?,?,?,?,?,?,?,?)",
                    (device_id, public_hex, _canonical(list(caps)).decode("utf-8"),
                     _canonical(list(scopes)).decode("utf-8"), enrollment_id,
                     nonce, certificate["expires_at"], timestamp),
                )
                self._audit(
                    connection, actor=signer_id, action="device.enroll",
                    resource=device_id, outcome="accepted",
                    details={"enrollment_id": enrollment_id, "capabilities": list(caps)},
                    timestamp=timestamp,
                )
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise DeviceEnrollmentError("device_already_enrolled_or_request_replayed") from exc
            except Exception:
                connection.execute("ROLLBACK")
                raise
        return enrollment_id

    def begin_authentication(self, device_id: str) -> dict[str, Any]:
        identifier = _device_id(device_id)
        now = int(self.clock())
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT revoked,expires_at FROM devices WHERE device_id=?",
                (identifier,),
            ).fetchone()
            if row is None or row[0] or row[1] < now:
                raise DeviceEnrollmentError("device_not_active")
            body = {
                "schema": CHALLENGE_SCHEMA,
                "session_id": secrets.token_hex(16),
                "device_id": identifier,
                "challenge": secrets.token_hex(16),
                "host_signer_id": self.host_signer_id,
                "issued_at": now,
                "expires_at": now + CHALLENGE_TTL,
            }
            challenge = {
                **body,
                "signature": _signature(self.host_private_key, CHALLENGE_DOMAIN, body),
            }
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO pending_sessions(session_id,device_id,challenge_json,expires_at) VALUES(?,?,?,?)",
                (body["session_id"], identifier,
                 _canonical(challenge).decode("utf-8"), body["expires_at"]),
            )
            self._audit(
                connection, actor=self.host_signer_id, action="device.challenge",
                resource=identifier, outcome="issued",
                details={"session_id": body["session_id"]}, timestamp=now,
            )
            connection.execute("COMMIT")
        return challenge

    def complete_authentication(self, response: Mapping[str, Any]) -> DeviceSession:
        if not isinstance(response, dict):
            raise DeviceEnrollmentError("device_response_object_required")
        fields = {
            "schema", "session_id", "device_id", "challenge",
            "issued_at", "expires_at", "signature",
        }
        if set(response) != fields or response["schema"] != RESPONSE_SCHEMA:
            raise DeviceEnrollmentError("device_response_schema_invalid")
        session_id = response["session_id"]
        device_id = _device_id(response["device_id"])
        if not isinstance(session_id, str) or not HEX_32.fullmatch(session_id):
            raise DeviceEnrollmentError("device_session_id_invalid")
        now = int(self.clock())
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT p.challenge_json,p.expires_at,p.consumed,d.public_key_hex,"
                "d.capabilities_json,d.scopes_json,d.revoked,d.expires_at "
                "FROM pending_sessions p JOIN devices d ON d.device_id=p.device_id "
                "WHERE p.session_id=? AND p.device_id=?",
                (session_id, device_id),
            ).fetchone()
            if row is None or row[2]:
                raise DeviceEnrollmentError("device_challenge_missing_or_consumed")
            if row[6] or row[7] < now:
                raise DeviceEnrollmentError("device_not_active")
            challenge = json.loads(row[0])
            if (response["challenge"] != challenge["challenge"]
                    or response["expires_at"] != challenge["expires_at"]
                    or row[1] < now):
                raise DeviceEnrollmentError("device_response_challenge_mismatch")
            _time_window(
                response["issued_at"], response["expires_at"], now,
                CHALLENGE_TTL, "device_response",
            )
            unsigned = {key: value for key, value in response.items() if key != "signature"}
            _verify_signature(
                _public_key(bytes.fromhex(row[3])), response["signature"],
                RESPONSE_DOMAIN, unsigned, "device_response_signature_invalid",
            )
            expires_at = min(now + SESSION_TTL, row[7])
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE pending_sessions SET consumed=1 WHERE session_id=? AND consumed=0",
                (session_id,),
            )
            if updated.rowcount != 1:
                connection.execute("ROLLBACK")
                raise DeviceEnrollmentError("device_challenge_replay")
            connection.execute(
                "INSERT INTO active_sessions(session_id,device_id,capabilities_json,scopes_json,expires_at) VALUES(?,?,?,?,?)",
                (session_id, device_id, row[4], row[5], expires_at),
            )
            self._audit(
                connection, actor=device_id, action="device.authenticate",
                resource=device_id, outcome="accepted",
                details={"session_id": session_id, "expires_at": expires_at},
                timestamp=now,
            )
            connection.execute("COMMIT")
        return DeviceSession(
            session_id=session_id, device_id=device_id,
            capabilities=tuple(json.loads(row[4])),
            scopes=tuple(json.loads(row[5])),
            expires_at=expires_at,
        )

    def authorize(
        self, session_id: str, capability: str, resource: str | None = None,
    ) -> bool:
        if (not isinstance(session_id, str) or not HEX_32.fullmatch(session_id)
                or not isinstance(capability, str)
                or capability not in SUPPORTED_CAPABILITIES
                or (resource is not None and
                    (not isinstance(resource, str) or not SCOPE.fullmatch(resource)))):
            return False
        now = int(self.clock())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT s.device_id,s.capabilities_json,s.scopes_json,s.expires_at,"
                "s.revoked,d.revoked,d.expires_at FROM active_sessions s "
                "JOIN devices d ON d.device_id=s.device_id WHERE s.session_id=?",
                (session_id,),
            ).fetchone()
            allowed = bool(
                row is not None
                and not row[4] and not row[5]
                and row[3] >= now and row[6] >= now
                and capability in json.loads(row[1])
                and (
                    (resource is not None and resource in json.loads(row[2]))
                    or (resource is None and capability == "device.status")
                )
            )
            self._audit(
                connection,
                actor="unknown" if row is None else row[0],
                action="device.authorize",
                resource=capability if resource is None else resource,
                outcome="allowed" if allowed else "denied",
                details={"session_id": session_id, "capability": capability},
                timestamp=now,
            )
            connection.execute("COMMIT")
        return allowed

    def revoke_device(self, revocation: Mapping[str, Any]) -> bool:
        if not isinstance(revocation, dict):
            raise DeviceEnrollmentError("device_revocation_object_required")
        fields = {
            "schema", "device_id", "signer_id", "issued_at",
            "expires_at", "nonce", "signature",
        }
        if set(revocation) != fields or revocation["schema"] != REVOCATION_SCHEMA:
            raise DeviceEnrollmentError("device_revocation_schema_invalid")
        identifier = _device_id(revocation["device_id"])
        signer_id = revocation["signer_id"]
        if not isinstance(signer_id, str) or not SIGNER_ID.fullmatch(signer_id):
            raise DeviceEnrollmentError("operator_signer_id_invalid")
        now = int(self.clock())
        _time_window(
            revocation["issued_at"], revocation["expires_at"], now,
            300, "device_revocation",
        )
        nonce = revocation["nonce"]
        if not isinstance(nonce, str) or not HEX_32.fullmatch(nonce):
            raise DeviceEnrollmentError("device_revocation_nonce_invalid")
        try:
            operator_key = _public_key(self.operator_trust[signer_id])
        except (KeyError, TypeError) as exc:
            raise DeviceEnrollmentError("operator_signer_untrusted") from exc
        unsigned = {key: value for key, value in revocation.items() if key != "signature"}
        _verify_signature(
            operator_key, revocation["signature"], REVOCATION_DOMAIN,
            unsigned, "device_revocation_signature_invalid",
        )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM revocation_nonces WHERE nonce=?", (nonce,)
            ).fetchone():
                connection.execute("ROLLBACK")
                raise DeviceEnrollmentError("device_revocation_replay")
            row = connection.execute(
                "SELECT revoked FROM devices WHERE device_id=?", (identifier,)
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                return False
            if row[0]:
                connection.execute(
                    "INSERT INTO revocation_nonces(nonce,device_id,signer_id,issued_at) VALUES(?,?,?,?)",
                    (nonce, identifier, signer_id, revocation["issued_at"]),
                )
                self._audit(
                    connection, actor=signer_id, action="device.revoke",
                    resource=identifier, outcome="already_revoked",
                    details={"nonce": nonce}, timestamp=now,
                )
                connection.execute("COMMIT")
                return True
            connection.execute(
                "INSERT INTO revocation_nonces(nonce,device_id,signer_id,issued_at) VALUES(?,?,?,?)",
                (nonce, identifier, signer_id, revocation["issued_at"]),
            )
            connection.execute(
                "UPDATE devices SET revoked=1 WHERE device_id=?", (identifier,)
            )
            connection.execute(
                "UPDATE active_sessions SET revoked=1 WHERE device_id=?", (identifier,)
            )
            self._audit(
                connection, actor=signer_id, action="device.revoke",
                resource=identifier, outcome="accepted",
                details={"nonce": nonce}, timestamp=now,
            )
            connection.execute("COMMIT")
        return True

    def verify_audit_chain(self) -> bool:
        with closing(self._connect()) as connection:
            return self._verify_audit(connection)

    def audit_events(self) -> tuple[dict[str, Any], ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT event_json FROM audit_events ORDER BY sequence"
            ).fetchall()
        return tuple(json.loads(row[0]) for row in rows)
