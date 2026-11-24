import base64
import gzip
import json
import unittest
from pathlib import Path

from src.consensus.gcf2_independent_verifier import verify_finality_certificate


class GCF2KnownAnswerVectorTests(unittest.TestCase):
    def test_python_generated_certificate_vector_verifies(self):
        encoded = Path(__file__).parent.joinpath(
            "vectors", "gcf2_finality_known_answer.json.gz.b64"
        ).read_text(encoding="ascii")
        vector = json.loads(gzip.decompress(base64.b64decode(encoded)))
        validators = {
            item["validator_id"]: {
                "public_key_hex": item["public_key_hex"],
                "weight": item["weight"],
            }
            for item in vector["validators"]
        }
        result = verify_finality_certificate(
            vector["certificate"], network_id=vector["network_id"],
            epoch=vector["epoch"], validators=validators,
            proposal=vector["proposal"],
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["candidate_digest"], vector["expected"]["candidate_digest"])
        self.assertEqual(result["validator_set_hash"], vector["validator_set_hash"])
        self.assertEqual(result["prevote_weight"], vector["expected"]["prevote_weight"])
        self.assertEqual(result["precommit_weight"], vector["expected"]["precommit_weight"])
        self.assertEqual(result["quorum_weight"], vector["expected"]["quorum_weight"])
        self.assertEqual(result["certificate_digest"], vector["expected"]["certificate_digest"])


if __name__ == "__main__":
    unittest.main()
