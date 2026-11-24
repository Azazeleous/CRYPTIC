import hashlib
import json
import unittest
import time

from src.sos.process_supervisor import (
    ProcessDeadlineExceeded,
    ProcessSupervisor,
    ProcessSupervisorError,
)


class ProcessSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.supervisor = ProcessSupervisor()

    def test_sha256_executes_in_a_separate_worker(self):
        payload = b"GAIA-NEXUS process boundary"
        result = self.supervisor.execute("sha256", payload, timeout_seconds=3)
        self.assertEqual(result.output.decode("ascii"), hashlib.sha256(payload).hexdigest())
        self.assertGreater(result.process_id, 0)
        self.assertGreaterEqual(result.elapsed_ms, 0)

    def test_text_stats_returns_bounded_canonical_metrics(self):
        result = self.supervisor.execute("text.stats", b"hi there\nok", timeout_seconds=3)
        self.assertEqual(json.loads(result.output), {
            "bytes": 11, "characters": 11, "lines": 2, "words": 3,
        })

    def test_json_canonicalization_is_deterministic_and_rejects_duplicate_keys(self):
        result = self.supervisor.execute(
            "json.canonicalize", b'{"b":2,"a":1}', timeout_seconds=3,
        )
        self.assertEqual(result.output, b'{"a":1,"b":2}')
        with self.assertRaisesRegex(ProcessSupervisorError, "worker_json_input_invalid"):
            self.supervisor.execute(
                "json.canonicalize", b'{"a":1,"a":2}', timeout_seconds=3,
            )

    def test_unknown_operation_and_oversized_input_are_rejected_before_spawn(self):
        with self.assertRaisesRegex(ProcessSupervisorError, "operation_not_allowed"):
            self.supervisor.execute("python.exec", b"print(1)")
        with self.assertRaisesRegex(ProcessSupervisorError, "input_size_invalid"):
            self.supervisor.execute("sha256", b"x" * (1024 * 1024 + 1))

    def test_absolute_deadline_terminates_worker(self):
        started = time.monotonic()
        with self.assertRaises(ProcessDeadlineExceeded) as raised:
            self.supervisor.execute(
                "diagnostic.pause", b'{"seconds":2}',
                timeout_seconds=0.2,
            )
        self.assertTrue(raised.exception.worker_terminated)
        self.assertIsNotNone(raised.exception.process_id)
        self.assertLess(time.monotonic() - started, 1.5)

    def test_already_expired_absolute_deadline_does_not_start_worker(self):
        with self.assertRaises(ProcessDeadlineExceeded) as raised:
            self.supervisor.execute(
                "sha256", b"payload",
                timeout_seconds=1,
                deadline_monotonic=time.monotonic() - 1,
            )
        self.assertFalse(raised.exception.worker_terminated)
        self.assertIsNone(raised.exception.process_id)


if __name__ == "__main__":
    unittest.main()
