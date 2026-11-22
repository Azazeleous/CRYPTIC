import base64,unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from src.mining.pool_protocol import issue_pool_job
from src.mining.pool_worker import execute_pool_job
from src.consensus.pool_admission import PoolAdmissionError,admit_pool_submission

class PoolAdmissionTests(unittest.TestCase):
    def setUp(self):
        key=Ed25519PrivateKey.generate()
        self.private_hex=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
        self.public_hex=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        self.job=issue_pool_job(private_key_hex=self.private_hex,issuer_id="issuer",pool_id="gaia-internal",network_id="hccgn-test",epoch=1,height=1,issued_at=1000,expires_at=1120,parent_hash="00"*32,payload_hash="11"*32,target="ff"*32,primary_stride=3037,compact_stride=5,nonce_start=0,max_attempts=8,job_id="cd"*16)
        self.submission=execute_pool_job(self.job,trusted_issuer_public_key_hex=self.public_hex,expected_pool_id="gaia-internal",expected_network_id="hccgn-test",worker_id="worker-a",now=1001)
    def admit(self,submission=None,target=None,worker="worker-a"):
        return admit_pool_submission(submission or self.submission,trusted_issuer_public_key_hex=self.public_hex,expected_pool_id="gaia-internal",expected_network_id="hccgn-test",authenticated_worker_id=worker,active_target_resolver=lambda job:bytes.fromhex(target or job["target"]),now=1002)
    def test_independent_verifier_accepts_real_hccgn_proof(self):
        result=self.admit()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["worker_id"],"worker-a")
        self.assertEqual(len(result["work_digest"]),64)
    def test_authenticated_worker_binding_is_required(self):
        with self.assertRaisesRegex(PoolAdmissionError,"worker_identity"):
            self.admit(worker="worker-b")
    def test_target_must_match_active_policy(self):
        with self.assertRaisesRegex(PoolAdmissionError,"not_active"):
            self.admit(target="00"*32)
    def test_measurement_claims_do_not_change_proof_verification(self):
        changed=dict(self.submission); changed["measurements"]={"attempts":-999,"hashes_per_second":float("nan")}
        self.assertTrue(self.admit(changed)["accepted"])

if __name__=="__main__": unittest.main()
