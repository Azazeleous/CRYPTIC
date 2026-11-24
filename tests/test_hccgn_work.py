import hashlib
import struct
import unittest

from src.consensus.hccgn_work import (
    HEADER_SIZE, HCCGNWorkError, HCCGNWorkHeader, HCCGNWorkProofProvider,
    build_proof, mine_nonce, network_hash, proof_commitment, verify_proof, work_digest,
)
from src.consensus.hccgn_adapter import HCCGNVerifierAdapter
from src.mining.symplectic import SCHEDULE_SYMPLECTIC, iter_symplectic_ordinals


class HCCGNWorkProfileTests(unittest.TestCase):
    def setUp(self):
        self.target = bytes.fromhex('ff' * 32)
        self.header = HCCGNWorkHeader(
            network_id_hash=network_hash('gaia-testnet'),
            height=1, sequence=1, timestamp=1700000000,
            parent_hash=bytes.fromhex('11' * 32),
            payload_hash=bytes.fromhex('22' * 32),
            primary_stride=5, compact_stride=7, nonce=42, target=self.target,
        )
        self.proof = build_proof(self.header)

    def test_known_answer_header_digest_and_commitment(self):
        self.assertEqual(HEADER_SIZE, 184)
        result = verify_proof(
            self.proof, expected_network_id='gaia-testnet', expected_target=self.target
        )
        self.assertTrue(result['valid'])
        self.assertEqual(result['inverse_verification'], {
            'primary_right_inverse': True, 'primary_left_inverse': True,
            'compact_right_inverse': True, 'compact_left_inverse': True,
        })
        self.assertEqual(result['profile_id'], 'HCCGN-WORK/1')
        self.assertEqual(result['work_digest'],
            'c823ee2a5d77e8576b1b4213bcdcca983b31c8b1c55743059f240957d9467f71')
        self.assertEqual(result['proof_hash'],
            'b48d21de1459758e3ffa8ed5a6e8a4488491787a4cd285bd93def24d3b36bb57')
        self.assertEqual(proof_commitment(self.proof), result['proof_hash'])

    def test_low_target_known_answer_fails(self):
        low = bytes.fromhex('00' + 'ff' * 31)
        header = HCCGNWorkHeader(
            network_id_hash=network_hash('gaia-testnet'), height=1, sequence=1,
            timestamp=1700000000, parent_hash=bytes.fromhex('11' * 32),
            payload_hash=bytes.fromhex('22' * 32), primary_stride=5,
            compact_stride=7, nonce=42, target=low,
        )
        proof = build_proof(header)
        with self.assertRaisesRegex(HCCGNWorkError, 'work_target_not_met'):
            verify_proof(proof, expected_network_id='gaia-testnet', expected_target=low)

    def test_active_target_is_not_proposer_selected(self):
        other = bytes.fromhex('00' + 'ff' * 31)
        with self.assertRaisesRegex(HCCGNWorkError, 'active_target_mismatch'):
            verify_proof(self.proof, expected_network_id='gaia-testnet', expected_target=other)

    def test_proposal_binding_is_enforced(self):
        proposal = {
            'network_id': 'gaia-testnet', 'epoch': 1, 'height': 1,
            'issued_at': 1700000000, 'parent_hash': '11' * 32,
            'payload_hash': '22' * 32,
        }
        result = verify_proof(self.proof, expected_network_id='gaia-testnet',
                              expected_target=self.target, proposal=proposal)
        self.assertTrue(result['valid'])
        proposal['height'] = 2
        with self.assertRaisesRegex(HCCGNWorkError, 'proposal_height_mismatch'):
            verify_proof(self.proof, expected_network_id='gaia-testnet',
                         expected_target=self.target, proposal=proposal)


    def test_midstate_digest_matches_full_sha256_for_multiple_nonces(self):
        for nonce in (0, 1, 42, 255, 65535):
            candidate = HCCGNWorkHeader(
                network_id_hash=self.header.network_id_hash, height=1, sequence=1,
                timestamp=1700000000, parent_hash=bytes.fromhex('11' * 32),
                payload_hash=bytes.fromhex('22' * 32), primary_stride=5,
                compact_stride=7, nonce=nonce, target=self.target,
            )
            stream = bytearray(b'HCCGN-WORK/1\x00' + candidate.encode())
            midstate = hashlib.sha256(stream[:128])
            tail = stream[128:]
            struct.pack_into('>Q', tail, 29, nonce)
            fast = midstate.copy()
            fast.update(tail)
            self.assertEqual(fast.digest(), work_digest(candidate.encode()))

    def test_midstate_miner_returns_independently_verifiable_proof(self):
        solved, digest, proof, proof_hash, attempts, elapsed = mine_nonce(
            self.header, start_nonce=42, max_attempts=1
        )
        self.assertEqual(solved.nonce, 42)
        self.assertEqual(digest, work_digest(solved.encode()))
        self.assertEqual(proof_hash, proof_commitment(proof))
        self.assertEqual(attempts, 1)
        self.assertGreaterEqual(elapsed, 0.0)
        result = verify_proof(
            proof, expected_network_id='gaia-testnet', expected_target=self.target
        )
        self.assertTrue(result['valid'])

    def test_symplectic_miner_uses_complete_bounded_nonce_permutation(self):
        offsets = tuple(iter_symplectic_ordinals(
            8, drift=self.header.primary_stride, kick=self.header.compact_stride,
        ))
        self.assertEqual(set(offsets), set(range(8)))
        solved, digest, proof, proof_hash, attempts, _elapsed = mine_nonce(
            self.header, start_nonce=200, max_attempts=8,
            schedule_profile=SCHEDULE_SYMPLECTIC,
        )
        self.assertEqual(solved.nonce, 200 + offsets[0])
        self.assertGreaterEqual(solved.nonce, 200)
        self.assertLess(solved.nonce, 208)
        self.assertEqual(digest, work_digest(solved.encode()))
        self.assertEqual(proof_hash, proof_commitment(proof))
        self.assertEqual(attempts, 1)
        self.assertTrue(verify_proof(
            proof, expected_network_id="gaia-testnet", expected_target=self.target,
        )["valid"])

    def test_unknown_nonce_schedule_profile_is_rejected(self):
        with self.assertRaisesRegex(HCCGNWorkError, "nonce_schedule_profile_unsupported"):
            mine_nonce(self.header, start_nonce=42, max_attempts=1, schedule_profile="unknown")

    def test_miner_rejects_nonce_range_wraparound(self):
        with self.assertRaisesRegex(HCCGNWorkError, 'nonce_range_overflow'):
            mine_nonce(self.header, start_nonce=(1 << 64) - 1, max_attempts=2)

    def test_boolean_version_is_rejected(self):
        bad = HCCGNWorkHeader(
            network_id_hash=network_hash('gaia-testnet'), height=1, sequence=1,
            timestamp=1700000000, parent_hash=bytes(32), payload_hash=bytes(32),
            primary_stride=5, compact_stride=7, nonce=0, target=self.target,
            version=True,
        )
        with self.assertRaisesRegex(HCCGNWorkError, 'version_must_be_integer'):
            bad.encode()

    def test_non_coprime_stride_is_rejected(self):
        bad = HCCGNWorkHeader(
            network_id_hash=network_hash('gaia-testnet'), height=1, sequence=1,
            timestamp=1700000000, parent_hash=bytes(32), payload_hash=bytes(32),
            primary_stride=2, compact_stride=7, nonce=0, target=self.target,
        )
        with self.assertRaisesRegex(HCCGNWorkError, 'primary_stride_not_coprime'):
            bad.encode()

    def test_tampered_envelope_is_rejected(self):
        damaged = self.proof[:-1] + bytes([self.proof[-1] ^ 1])
        with self.assertRaisesRegex(HCCGNWorkError, 'work_digest_mismatch'):
            verify_proof(damaged, expected_network_id='gaia-testnet',
                         expected_target=self.target)

    def test_adapter_provider_binds_proof_hash_and_profile(self):
        proof_hash = proof_commitment(self.proof)
        proposal = {
            'network_id': 'gaia-testnet', 'epoch': 1, 'height': 1,
            'issued_at': 1700000000, 'parent_hash': '11' * 32,
            'payload_hash': '22' * 32, 'proof_hash': proof_hash,
        }
        provider = HCCGNWorkProofProvider(
            resolve_proof=lambda digest: self.proof if digest == proof_hash else None,
            resolve_target=lambda _proposal: self.target,
        )
        gate = HCCGNVerifierAdapter(provider, profile_id='HCCGN-WORK/1')
        result = gate(proposal)
        self.assertTrue(result.allowed, result.reason)


if __name__ == '__main__':
    unittest.main()