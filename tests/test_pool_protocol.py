import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from src.mining.pool_protocol import PoolJobError,issue_pool_job,verify_pool_job
from src.mining.pool_worker import execute_pool_job

class PoolProtocolTests(unittest.TestCase):
    def setUp(self):
        self.private=Ed25519PrivateKey.generate()
        self.private_hex=self.private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
        self.public_hex=self.private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        self.job=issue_pool_job(private_key_hex=self.private_hex,issuer_id="pool-issuer",pool_id="gaia-internal",network_id="hccgn-test",epoch=1,height=1,issued_at=1000,expires_at=1120,parent_hash="00"*32,payload_hash="11"*32,target="ff"*32,primary_stride=3037,compact_stride=5,nonce_start=0,max_attempts=8,job_id="ab"*16)
    def test_signed_job_round_trip(self):
        result=verify_pool_job(self.job,trusted_issuer_public_key_hex=self.public_hex,expected_issuer_id="pool-issuer",expected_pool_id="gaia-internal",expected_network_id="hccgn-test",now=1001)
        self.assertEqual(result["job_id"],"ab"*16)
    def test_tampered_target_fails_signature(self):
        changed=dict(self.job); changed["target"]="00"*32
        with self.assertRaisesRegex(PoolJobError,"signature"):
            verify_pool_job(changed,trusted_issuer_public_key_hex=self.public_hex,expected_issuer_id="pool-issuer",expected_pool_id="gaia-internal",expected_network_id="hccgn-test",now=1001)
    def test_expired_job_rejected(self):
        with self.assertRaisesRegex(PoolJobError,"expired"):
            verify_pool_job(self.job,trusted_issuer_public_key_hex=self.public_hex,expected_issuer_id="pool-issuer",expected_pool_id="gaia-internal",expected_network_id="hccgn-test",now=1121)
    def test_worker_executes_bounded_job(self):
        result=execute_pool_job(self.job,trusted_issuer_public_key_hex=self.public_hex,expected_issuer_id="pool-issuer",expected_pool_id="gaia-internal",expected_network_id="hccgn-test",expected_issuer_id="pool-issuer",worker_id="hp-aio",now=1001)
        self.assertEqual(result["schema"],"CRYPTIC-POOL-SUBMISSION/1")
        self.assertEqual(result["worker_id"],"hp-aio")
        self.assertLessEqual(result["measurements"]["attempts"],8)
        self.assertEqual(len(result["proof_hash"]),64)

if __name__=="__main__": unittest.main()
