"""Bounded HCCGN pool worker: verify signed jobs, mine, and serialize shares."""
from __future__ import annotations
import base64
from typing import Any,Mapping
from src.consensus.hccgn_work import HCCGNWorkHeader,mine_nonce,network_hash,proof_commitment
from src.mining.pool_protocol import verify_pool_job

class PoolWorkerError(ValueError):
    """Worker could not safely execute or submit a pool job."""

def execute_pool_job(job:Mapping[str,Any],*,trusted_issuer_public_key_hex:str,expected_pool_id:str,expected_network_id:str,worker_id:str,now:int)->dict:
    """Execute exactly the signed nonce window and return a proof submission."""
    if not isinstance(worker_id,str) or not worker_id or len(worker_id.encode("utf-8"))>256: raise PoolWorkerError("worker_id_invalid")
    body=verify_pool_job(job,trusted_issuer_public_key_hex=trusted_issuer_public_key_hex,expected_pool_id=expected_pool_id,expected_network_id=expected_network_id,now=now)
    try:
        header=HCCGNWorkHeader(network_hash(body["network_id"]),body["height"],body["epoch"],body["issued_at"],bytes.fromhex(body["parent_hash"]),bytes.fromhex(body["payload_hash"]),body["primary_stride"],body["compact_stride"],body["nonce_start"],bytes.fromhex(body["target"]))
        solved,digest,proof,proof_hash,attempts,elapsed=mine_nonce(header,start_nonce=body["nonce_start"],max_attempts=body["max_attempts"])
    except Exception as exc: raise PoolWorkerError("bounded_job_execution_failed") from exc
    return {"schema":"CRYPTIC-POOL-SUBMISSION/1","pool_id":body["pool_id"],"job_id":body["job_id"],"job":dict(job),"worker_id":worker_id,"proof_hash":proof_hash,"proof_b64":base64.b64encode(proof).decode("ascii"),"submitted_at":now,"measurements":{"attempts":attempts,"elapsed_seconds":elapsed,"hashes_per_second":attempts/elapsed if elapsed>0 else None,"nonce":solved.nonce,"work_digest":digest.hex(),"proof_commitment":proof_commitment(proof)}}
