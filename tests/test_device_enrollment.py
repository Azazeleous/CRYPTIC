import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.device.enrollment import (
    DeviceEnrollmentError,
    DeviceRegistry,
    make_device_response,
    make_device_revocation,
    make_enrollment_certificate,
    make_enrollment_request,
)


def keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return private, public


class DeviceEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1_800_000_000
        self.device_private, self.device_public = keypair()
        self.operator_private, self.operator_public = keypair()
        self.host_private, self.host_public = keypair()
        self.registry = DeviceRegistry(
            Path(self.temp.name) / "devices.sqlite3",
            operator_trust={"operator-root": self.operator_public},
            host_signer_id="host-root",
            host_private_key=self.host_private,
            clock=lambda: self.now,
        )
        self.request = make_enrollment_request(
            device_id="samsung-a15-controller",
            device_private_key=self.device_private,
            capabilities=[
                "ble.observe", "device.status", "home.read", "network.read",
            ],
            scopes=[
                "ble:AA:BB:CC:DD:EE:FF", "home:thermostat-1", "network:lan",
            ],
            issued_at=self.now - 1,
            expires_at=self.now + 300,
            consent=True,
            nonce="1" * 32,
        )
        self.certificate = make_enrollment_certificate(
            self.request,
            operator_private_key=self.operator_private,
            signer_id="operator-root",
            capabilities=["device.status", "network.read"],
            scopes=["network:lan"],
            issued_at=self.now - 1,
            expires_at=self.now + 86400,
            enrollment_id="2" * 32,
        )

    def enroll_and_authenticate(self):
        self.registry.enroll(self.request, self.certificate)
        challenge = self.registry.begin_authentication("samsung-a15-controller")
        response = make_device_response(
            challenge,
            device_private_key=self.device_private,
            host_public_key=self.host_public,
            expected_host_signer_id="host-root",
            now=self.now,
        )
        return challenge, response, self.registry.complete_authentication(response)

    def test_consent_bound_enrollment_and_mutual_authentication(self):
        _challenge, _response, session = self.enroll_and_authenticate()
        self.assertEqual(session.device_id, "samsung-a15-controller")
        self.assertEqual(session.capabilities, ("device.status", "network.read"))
        self.assertTrue(self.registry.authorize(
            session.session_id, "network.read", "network:lan",
        ))
        self.assertTrue(self.registry.authorize(
            session.session_id, "device.status",
        ))
        self.assertFalse(self.registry.authorize(
            session.session_id, "network.read", "network:other",
        ))
        self.assertFalse(self.registry.authorize(
            session.session_id, "home.read", "home:thermostat-1",
        ))
        self.assertTrue(self.registry.verify_audit_chain())

    def test_explicit_consent_is_mandatory(self):
        with self.assertRaisesRegex(DeviceEnrollmentError, "explicit_device_consent_required"):
            make_enrollment_request(
                device_id="samsung-a15-controller",
                device_private_key=self.device_private,
                capabilities=["device.status"],
                scopes=["device:status"],
                issued_at=self.now,
                expires_at=self.now + 60,
                consent=False,
            )

    def test_device_request_signature_and_operator_certificate_are_verified(self):
        tampered_request = {**self.request, "requested_scopes": ["network:other"]}
        with self.assertRaisesRegex(DeviceEnrollmentError, "device_request_signature_invalid"):
            self.registry.enroll(tampered_request, self.certificate)

        tampered_certificate = {**self.certificate, "scopes": ["home:thermostat-1"]}
        with self.assertRaisesRegex(DeviceEnrollmentError, "enrollment_certificate_signature_invalid"):
            self.registry.enroll(self.request, tampered_certificate)

    def test_operator_cannot_grant_more_than_device_consented(self):
        with self.assertRaisesRegex(DeviceEnrollmentError, "operator_certificate_exceeds_device_consent"):
            make_enrollment_certificate(
                self.request,
                operator_private_key=self.operator_private,
                signer_id="operator-root",
                capabilities=["network.read"],
                scopes=["home:other"],
                issued_at=self.now,
                expires_at=self.now + 300,
            )

    def test_host_challenge_tampering_is_detected_before_device_signs(self):
        self.registry.enroll(self.request, self.certificate)
        challenge = self.registry.begin_authentication("samsung-a15-controller")
        tampered = {**challenge, "challenge": "f" * 32}
        with self.assertRaisesRegex(DeviceEnrollmentError, "host_challenge_signature_invalid"):
            make_device_response(
                tampered,
                device_private_key=self.device_private,
                host_public_key=self.host_public,
                expected_host_signer_id="host-root",
                now=self.now,
            )

    def test_challenge_response_replay_is_rejected(self):
        _challenge, response, _session = self.enroll_and_authenticate()
        with self.assertRaisesRegex(DeviceEnrollmentError, "missing_or_consumed"):
            self.registry.complete_authentication(response)

    def test_device_revocation_invalidates_existing_sessions(self):
        _challenge, _response, session = self.enroll_and_authenticate()
        revocation = make_device_revocation(
            device_id="samsung-a15-controller",
            operator_private_key=self.operator_private,
            signer_id="operator-root",
            issued_at=self.now,
            expires_at=self.now + 120,
            nonce="3" * 32,
        )
        self.assertTrue(self.registry.revoke_device(revocation))
        self.assertFalse(self.registry.authorize(
            session.session_id, "network.read", "network:lan",
        ))
        with self.assertRaisesRegex(DeviceEnrollmentError, "device_not_active"):
            self.registry.begin_authentication("samsung-a15-controller")

    def test_unsigned_or_replayed_revocation_is_rejected(self):
        self.registry.enroll(self.request, self.certificate)
        revocation = make_device_revocation(
            device_id="samsung-a15-controller",
            operator_private_key=self.operator_private,
            signer_id="operator-root",
            issued_at=self.now,
            expires_at=self.now + 120,
            nonce="4" * 32,
        )
        forged = {**revocation, "device_id": "another-device"}
        with self.assertRaisesRegex(DeviceEnrollmentError, "signature_invalid"):
            self.registry.revoke_device(forged)
        self.assertTrue(self.registry.revoke_device(revocation))
        with self.assertRaisesRegex(DeviceEnrollmentError, "device_revocation_replay"):
            self.registry.revoke_device(revocation)

    def test_expired_session_is_not_authorized(self):
        _challenge, _response, session = self.enroll_and_authenticate()
        self.now += 901
        self.assertFalse(self.registry.authorize(
            session.session_id, "network.read", "network:lan",
        ))

    def test_duplicate_enrollment_and_nonce_replay_are_rejected(self):
        self.registry.enroll(self.request, self.certificate)
        with self.assertRaisesRegex(DeviceEnrollmentError, "already_enrolled_or_request_replayed"):
            self.registry.enroll(self.request, self.certificate)

    def test_audit_tampering_blocks_new_authentication_challenges(self):
        self.registry.enroll(self.request, self.certificate)
        with sqlite3.connect(self.registry.database) as connection:
            connection.execute(
                "UPDATE audit_events SET event_json=? WHERE sequence=1",
                ('{"sequence":1,"tampered":true}',),
            )
        self.assertFalse(self.registry.verify_audit_chain())
        with self.assertRaisesRegex(DeviceEnrollmentError, "audit_chain_integrity_failure"):
            self.registry.begin_authentication("samsung-a15-controller")


if __name__ == "__main__":
    unittest.main()
