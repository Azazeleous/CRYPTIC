import importlib.util, os, tempfile, unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "cryptic-seed-ledger.py"
SPEC = importlib.util.spec_from_file_location("cryptic_seed_ledger", SCRIPT)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

class SeedLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / ".cryptic"
        mod.init_state(self.state)
    def tearDown(self): self.tmp.cleanup()
    def test_append_verify_and_root_invalidation(self):
        mod.append_event(self.state, "test.one", {"value": 1})
        first = mod.write_root(self.state)
        self.assertTrue(first["valid"])
        mod.append_event(self.state, "test.two", {"value": 2})
        self.assertTrue(mod.verify_state(self.state)["valid"])
    def test_tamper_is_detected(self):
        mod.append_event(self.state, "test.one", {"value": 1})
        p = mod.paths(self.state)[1]
        p.write_text(p.read_text().replace('"value":1', '"value":9'))
        with self.assertRaisesRegex(ValueError, "record hash mismatch"): mod.verify_state(self.state)
    def test_seed_commitment_mismatch_is_detected(self):
        mod.append_event(self.state, "test.one", {"value": 1})
        seed = mod.paths(self.state)[0]
        seed.write_bytes(os.urandom(32)); os.chmod(seed, 0o600)
        with self.assertRaisesRegex(ValueError, "seed commitment mismatch"): mod.verify_state(self.state)
    def test_noncanonical_json_is_rejected(self):
        mod.append_event(self.state, "test.one", {"value": 1})
        p = mod.paths(self.state)[1]; p.write_text(p.read_text().replace("{", "{ ", 1))
        with self.assertRaisesRegex(ValueError, "non-canonical"): mod.verify_state(self.state)
    def test_invalid_event_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "event_type"): mod.append_event(self.state, "../bad", {})
    def test_audit_detects_dynamic_eval_and_hidden_bidi(self):
        sample = Path(self.tmp.name) / "sample.py"
        sample.write_text("eval(user_input)\n# hidden: \u202e\n")
        findings = mod.audit_path(sample)
        categories = {x["category"] for x in findings}
        self.assertIn("dynamic-evaluation", categories)
        self.assertIn("bidirectional-control-character", categories)
    def test_merkle_proof_root_changes_when_leaf_changes(self):
        a = mod.merkle_root(["1" * 64, "2" * 64])
        b = mod.merkle_root(["1" * 64, "3" * 64])
        self.assertNotEqual(a, b)

if __name__ == "__main__": unittest.main()
