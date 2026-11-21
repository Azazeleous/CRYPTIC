import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "schemas" / "crystalline" / "v1"
EXPECTED = {
    "candidate.schema.json",
    "adam-policy.schema.json",
    "adam-decision.schema.json",
    "tdoc-transition.schema.json",
    "checkpoint.schema.json",
}


class CrystallineSchemaTests(unittest.TestCase):
    def test_expected_schema_set_is_present(self):
        actual = {path.name for path in SCHEMA_DIR.glob("*.schema.json")}
        self.assertEqual(actual, EXPECTED)

    def test_all_schemas_are_valid_draft_2020_12(self):
        for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
            with self.subTest(schema=path.name):
                schema = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(
                    schema.get("$schema"),
                    "https://json-schema.org/draft/2020-12/schema",
                )
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema, format_checker=FormatChecker())

    def test_adam_policy_is_default_deny(self):
        schema = json.loads(
            (SCHEMA_DIR / "adam-policy.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["properties"]["default_decision"]["const"], "DENY"
        )

    def test_decision_schema_prevents_grants_on_deny_or_quarantine(self):
        schema = json.loads(
            (SCHEMA_DIR / "adam-decision.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(schema["allOf"]), 3)
        for rule in schema["allOf"][:2]:
            self.assertEqual(rule["then"]["properties"]["granted_capabilities"]["maxItems"], 0)


if __name__ == "__main__":
    unittest.main()
