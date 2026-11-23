import tempfile
import unittest
from pathlib import Path

from src.consensus.gcf import ValidatorSet, public_key_hex
from src.consensus.round_change import (
    make_round_change_certificate, make_round_change_message,
)
from src.consensus.round_progression import (
    RoundProgressionController, RoundProgressionError,
)


class _Engine:
    def __init__(self, vset, clock):
        self.validator_set = vset
        self.clock = clock


class RoundProgressionControllerTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.monotonic_now = 100.0
        self.private = {f"v{i}": (bytes([i]) * 32).hex() for i in range(1, 5)}
        self.vset = ValidatorSet("test-net", 7, {
            name: {"public_key_hex": public_key_hex(key), "weight": 1}
            for name, key in self.private.items()
        })
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "progression.sqlite3"
        self.engine = _Engine(self.vset, lambda: self.now)
        self.controller = RoundProgressionController(
            engine=self.engine, database=self.db,
            monotonic=lambda: self.monotonic_now,
        )

    def tearDown(self):
        self.temp.cleanup()

    def certificate(self, target=1):
        messages = [
            make_round_change_message(
                validator_id=name, private_key_hex=self.private[name],
                network_id="test-net", epoch=7, height=12,
                source_round=0, target_round=target,
                issued_at=self.now, expires_at=self.now + 60,
                nonce=str(index) * 32,
            )
            for index, name in enumerate(("v1", "v2", "v3"), start=1)
        ]
        return make_round_change_certificate(
            messages, network_id="test-net", epoch=7,
            height=12, target_round=target,
        )

    def test_timeout_emits_durable_intent_without_advancing_or_unlocking(self):
        self.controller.arm(height=12)
        self.assertIsNone(self.controller.poll_timeout(height=12, now_monotonic=104.99))
        event = self.controller.poll_timeout(height=12, now_monotonic=105.0)
        self.assertEqual(event["action"], "REQUEST_SIGNED_ROUND_CHANGE")
        self.assertEqual(event["target_round"], 1)
        self.assertFalse(event["signing_authorized"])
        self.assertFalse(event["lock_released"])
        self.assertEqual(self.controller.current_round(12), 0)
        self.assertEqual(
            self.controller.poll_timeout(height=12, now_monotonic=106.0), event
        )
        self.assertTrue(self.controller.acknowledge_timeout(height=12, source_round=0))
        self.assertFalse(self.controller.acknowledge_timeout(height=12, source_round=0))

    def test_only_verified_next_round_certificate_advances_and_survives_restart(self):
        self.assertEqual(self.controller.current_round(12), 0)
        cert = self.certificate()
        result = self.controller.activate_certificate(cert, height=12)
        self.assertTrue(result["advanced"])
        self.assertFalse(result["signing_authorized"])
        self.assertFalse(result["lock_released"])
        self.assertEqual(self.controller.current_round(12), 1)
        restored = self.controller.get_certificate(height=12, target_round=1)
        self.assertEqual(restored["digest"], cert["digest"])

        restarted = RoundProgressionController(
            engine=self.engine, database=self.db,
            monotonic=lambda: self.monotonic_now,
        )
        self.assertEqual(restarted.current_round(12), 1)
        self.assertEqual(
            restarted.get_certificate(height=12, target_round=1)["digest"],
            cert["digest"],
        )

    def test_timeout_cannot_advance_without_a_certificate(self):
        self.controller.arm(height=12)
        self.controller.poll_timeout(height=12, now_monotonic=105.0)
        self.assertEqual(self.controller.current_round(12), 0)
        with self.assertRaisesRegex(RoundProgressionError, "certificate_required"):
            self.controller.activate_certificate(None, height=12)
        self.assertEqual(self.controller.current_round(12), 0)

    def test_certificate_must_advance_exactly_one_round(self):
        cert = self.certificate(target=2)
        with self.assertRaisesRegex(
            RoundProgressionError, "exactly_one_round",
        ):
            self.controller.activate_certificate(cert, height=12)
        self.assertEqual(self.controller.current_round(12), 0)

    def test_insufficient_quorum_certificate_is_rejected(self):
        cert = self.certificate()
        cert["messages"] = cert["messages"][:2]
        from src.consensus.gcf import canonical_bytes, sha256_hex
        from src.consensus.round_change import ROUND_CHANGE_CERT_DOMAIN
        body = {key: value for key, value in cert.items() if key != "digest"}
        cert["digest"] = sha256_hex(
            ROUND_CHANGE_CERT_DOMAIN + canonical_bytes(body)
        )
        with self.assertRaisesRegex(RoundProgressionError, "certificate_invalid"):
            self.controller.activate_certificate(cert, height=12)
        self.assertEqual(self.controller.current_round(12), 0)

    def test_round_must_be_armed_before_timeout_poll(self):
        with self.assertRaisesRegex(RoundProgressionError, "not_armed"):
            self.controller.poll_timeout(height=12, now_monotonic=200.0)


if __name__ == "__main__":
    unittest.main()
