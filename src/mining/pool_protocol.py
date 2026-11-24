"""Signed, bounded CRYPTIC pool jobs for the canonical HCCGN-WORK/1 profile."""
from __future__ import annotations
import base64, json, re
from typing import Any, Mapping
from src.consensus.hccgn_work import HCCGNWorkHeader, network_hash

POOL_JOB_SCHEMA = "CRYPTIC-POOL-JOB/1"
POOL_JOB_DOMAIN = b"CRYPTIC-POOL-JOB/1\x00"
MAX_JOB_ATTEMPTS = 10_000_000
MAX_JOB_LIFETIME_SECONDS = 300
HEX32 = re.compile(r"^[0-9a-f]{64}$")
JOB_ID = re.compile(r"^[0-9a-f]{32}$")
FIELDS = {"schema","pool_id","issuer_id","job_id","network_id","epoch","height","issued_at","expires_at","parent_hash","payload_hash","target","primary_stride","compact_stride","nonce_start","max_attempts"}

class PoolJobError(ValueError):
    """A pool job is malformed, unauthenticated, expired, or out of bounds."""

def _uint(value: Any, name: str, minimum: int = 0, maximum: int = (1 << 63)-1) -> int:
    if isinstance(value,bool) or not isinstance(value,int) or not minimum <= value <= maximum:
        raise PoolJobError(name+"_invalid")
    return value

def canonical_bytes(value: Mapping[str,Any]) -> bytes:
    try:
        return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
    except (TypeError,ValueError,UnicodeEncodeError) as exc:
        raise PoolJobError("canonical_encoding_invalid") from exc

def _private_key(value: str):
    if not isinstance(value,str) or not re.fullmatch(r"[0-9a-fA-F]{64}",value):
        raise PoolJobError("issuer_private_key_invalid")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))
    except Exception as exc:
        raise PoolJobError("issuer_private_key_invalid") from exc

def issue_pool_job(*,private_key_hex:str,issuer_id:str,pool_id:str,network_id:str,epoch:int,height:int,issued_at:int,expires_at:int,parent_hash:str,payload_hash:str,target:str,primary_stride:int,compact_stride:int,nonce_start:int,max_attempts:int,job_id:str)->dict:
    """Create an issuer-signed job; target must come from authenticated policy."""
    for name,value in (("issuer_id",issuer_id),("pool_id",pool_id),("network_id",network_id)):
        if not isinstance(value,str) or not value or len(value.encode("utf-8"))>256: raise PoolJobError(name+"_invalid")
    if not isinstance(job_id,str) or not JOB_ID.fullmatch(job_id): raise PoolJobError("job_id_invalid")
    epoch=_uint(epoch,"epoch",1); height=_uint(height,"height",1)
    issued_at=_uint(issued_at,"issued_at",1); expires_at=_uint(expires_at,"expires_at",1)
    nonce_start=_uint(nonce_start,"nonce_start",0,(1<<64)-1)
    max_attempts=_uint(max_attempts,"max_attempts",1,MAX_JOB_ATTEMPTS)
    if expires_at<=issued_at or expires_at-issued_at>MAX_JOB_LIFETIME_SECONDS: raise PoolJobError("job_lifetime_invalid")
    if nonce_start+max_attempts>(1<<64): raise PoolJobError("nonce_range_overflow")
    for name,value in (("parent_hash",parent_hash),("payload_hash",payload_hash),("target",target)):
        if not isinstance(value,str) or not HEX32.fullmatch(value): raise PoolJobError(name+"_invalid")
    try:
        HCCGNWorkHeader(network_hash(network_id),height,epoch,issued_at,bytes.fromhex(parent_hash),bytes.fromhex(payload_hash),primary_stride,compact_stride,nonce_start,bytes.fromhex(target)).encode()
    except Exception as exc: raise PoolJobError("work_header_parameters_invalid") from exc
    body={"schema":POOL_JOB_SCHEMA,"pool_id":pool_id,"issuer_id":issuer_id,"job_id":job_id,"network_id":network_id,"epoch":epoch,"height":height,"issued_at":issued_at,"expires_at":expires_at,"parent_hash":parent_hash,"payload_hash":payload_hash,"target":target,"primary_stride":primary_stride,"compact_stride":compact_stride,"nonce_start":nonce_start,"max_attempts":max_attempts}
    body["signature"]=base64.b64encode(_private_key(private_key_hex).sign(POOL_JOB_DOMAIN+canonical_bytes(body))).decode("ascii")
    return body

def verify_pool_job(job:Mapping[str,Any],*,trusted_issuer_public_key_hex:str,expected_issuer_id:str,expected_pool_id:str,expected_network_id:str,now:int)->dict:
    """Verify exact schema, issuer signature, network/pool binding, time and bounds."""
    if not isinstance(job,Mapping) or set(job)!=FIELDS|{"signature"}: raise PoolJobError("job_fields_invalid")
    body=dict(job); signature_text=body.pop("signature")
    if body["schema"]!=POOL_JOB_SCHEMA: raise PoolJobError("job_schema_invalid")
    if body["pool_id"]!=expected_pool_id or body["network_id"]!=expected_network_id: raise PoolJobError("job_scope_mismatch")
    if not isinstance(expected_issuer_id,str) or not expected_issuer_id or body["issuer_id"]!=expected_issuer_id: raise PoolJobError("issuer_identity_mismatch")
    if not isinstance(trusted_issuer_public_key_hex,str) or not re.fullmatch(r"[0-9a-fA-F]{64}",trusted_issuer_public_key_hex): raise PoolJobError("issuer_public_key_invalid")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_issuer_public_key_hex)).verify(base64.b64decode(signature_text,validate=True),POOL_JOB_DOMAIN+canonical_bytes(body))
    except Exception as exc: raise PoolJobError("job_signature_invalid") from exc
    _uint(body["epoch"],"epoch",1); _uint(body["height"],"height",1)
    issued=_uint(body["issued_at"],"issued_at",1); expires=_uint(body["expires_at"],"expires_at",1); current=_uint(now,"now",0)
    if expires<=issued or expires-issued>MAX_JOB_LIFETIME_SECONDS: raise PoolJobError("job_lifetime_invalid")
    if current<issued or current>expires: raise PoolJobError("job_expired_or_not_yet_valid")
    nonce_start=_uint(body["nonce_start"],"nonce_start",0,(1<<64)-1); attempts=_uint(body["max_attempts"],"max_attempts",1,MAX_JOB_ATTEMPTS)
    if nonce_start+attempts>(1<<64): raise PoolJobError("nonce_range_overflow")
    if not isinstance(body["job_id"],str) or not JOB_ID.fullmatch(body["job_id"]): raise PoolJobError("job_id_invalid")
    for name in ("parent_hash","payload_hash","target"):
        if not isinstance(body[name],str) or not HEX32.fullmatch(body[name]): raise PoolJobError(name+"_invalid")
    try:
        HCCGNWorkHeader(network_hash(body["network_id"]),body["height"],body["epoch"],body["issued_at"],bytes.fromhex(body["parent_hash"]),bytes.fromhex(body["payload_hash"]),body["primary_stride"],body["compact_stride"],nonce_start,bytes.fromhex(body["target"])).encode()
    except Exception as exc: raise PoolJobError("work_header_parameters_invalid") from exc
    return body
