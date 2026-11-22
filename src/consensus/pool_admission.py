"""Independent admission of signed HCCGN pool jobs and worker proof submissions."""
from __future__ import annotations
import base64,hashlib,re
from typing import Any,Callable,Mapping
from src.consensus.hccgn_work import proof_commitment,verify_proof
from src.mining.pool_protocol import PoolJobError,verify_pool_job

SUBMISSION_FIELDS={"schema","pool_id","job_id","job","worker_id","proof_hash","proof_b64","submitted_at","measurements"}
HEX32=re.compile(r"^[0-9a-f]{64}$")
MAX_PROOF_BYTES=4096

class PoolAdmissionError(ValueError):
    """A submitted share failed an independent pool admission predicate."""

def admit_pool_submission(submission:Mapping[str,Any],*,trusted_issuer_public_key_hex:str,expected_issuer_id:str,expected_pool_id:str,expected_network_id:str,authenticated_worker_id:str,active_target_resolver:Callable[[Mapping[str,Any]],bytes|None],now:int)->dict:
    """Verify issuer job, authenticated worker binding, active target and HCCGN proof.

    The worker's measurements are deliberately ignored; only recomputed proof
    bytes and the independently resolved active target determine admission.
    """
    if not isinstance(submission,Mapping) or set(submission)!=SUBMISSION_FIELDS: raise PoolAdmissionError("submission_fields_invalid")
    if submission.get("schema")!="CRYPTIC-POOL-SUBMISSION/1": raise PoolAdmissionError("submission_schema_invalid")
    worker_id=submission.get("worker_id")
    if not isinstance(authenticated_worker_id,str) or not authenticated_worker_id or worker_id!=authenticated_worker_id: raise PoolAdmissionError("worker_identity_binding_failed")
    try:
        job=verify_pool_job(submission["job"],trusted_issuer_public_key_hex=trusted_issuer_public_key_hex,expected_issuer_id=expected_issuer_id,expected_pool_id=expected_pool_id,expected_network_id=expected_network_id,now=now)
    except (PoolJobError,KeyError) as exc: raise PoolAdmissionError("job_invalid:"+str(exc)) from exc
    if submission["pool_id"]!=job["pool_id"] or submission["job_id"]!=job["job_id"]: raise PoolAdmissionError("submission_job_binding_failed")
    submitted_at=submission["submitted_at"]
    if isinstance(submitted_at,bool) or not isinstance(submitted_at,int) or not job["issued_at"]<=submitted_at<=job["expires_at"] or submitted_at>now: raise PoolAdmissionError("submission_time_invalid")
    proof_hash=submission["proof_hash"]
    if not isinstance(proof_hash,str) or not HEX32.fullmatch(proof_hash): raise PoolAdmissionError("proof_hash_invalid")
    try: proof=base64.b64decode(submission["proof_b64"],validate=True)
    except Exception as exc: raise PoolAdmissionError("proof_encoding_invalid") from exc
    if not proof or len(proof)>MAX_PROOF_BYTES: raise PoolAdmissionError("proof_size_invalid")
    if proof_commitment(proof)!=proof_hash: raise PoolAdmissionError("proof_commitment_mismatch")
    try: active_target=active_target_resolver(job)
    except Exception as exc: raise PoolAdmissionError("active_target_unavailable") from exc
    if not isinstance(active_target,bytes) or len(active_target)!=32: raise PoolAdmissionError("active_target_invalid")
    if active_target.hex()!=job["target"]: raise PoolAdmissionError("job_target_not_active")
    proposal={"network_id":expected_network_id,"height":job["height"],"epoch":job["epoch"],"issued_at":job["issued_at"],"parent_hash":job["parent_hash"],"payload_hash":job["payload_hash"]}
    try: verified=verify_proof(proof,expected_network_id=expected_network_id,expected_target=active_target,proposal=proposal)
    except Exception as exc: raise PoolAdmissionError("hccgn_proof_rejected:"+type(exc).__name__) from exc
    if verified.get("valid") is not True or verified.get("proof_hash")!=proof_hash: raise PoolAdmissionError("hccgn_proof_rejected")
    identity={"network_id":expected_network_id,"pool_id":expected_pool_id,"job_id":job["job_id"],"worker_id":worker_id,"proof_hash":proof_hash}
    share_id=hashlib.sha256(repr(sorted(identity.items())).encode("utf-8")).hexdigest()
    return {"accepted":True,"share_id":share_id,**identity,"work_digest":verified["work_digest"],"nonce":verified["nonce"],"target":verified["target"],"accepted_at":now,"profile_id":verified["profile_id"]}
