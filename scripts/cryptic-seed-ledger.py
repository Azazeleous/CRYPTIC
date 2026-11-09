#!/usr/bin/env python3
"""CRYPTIC seed commitment, append-only hash chain, Merkle receipts, and source audit.

Standard-library only. The secret seed is created locally and is never printed.
This tool detects tampering; a trusted external checkpoint is still required to
prevent an attacker with write access from rewriting the entire local history.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, secrets, stat, sys, tempfile, unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FORMAT = "cryptic-seed-ledger/v1"
MAX_PAYLOAD_BYTES = 1_048_576
DIGEST = "blake2b-256"
ZERO = "0" * 64
ROUTING_PROFILE = {"modulus": 97152, "factorization": [[2, 7], [3, 1], [11, 1], [23, 1]], "totient": 28160, "role": "public-deterministic-traversal-profile-not-a-secret-or-hash-preimage"}


def normalize_json(value: Any) -> Any:
    if isinstance(value, str): return unicodedata.normalize("NFC", value)
    if isinstance(value, list): return [normalize_json(v) for v in value]
    if isinstance(value, dict):
        out={}
        for key, item in value.items():
            if not isinstance(key, str): raise ValueError("JSON object keys must be strings")
            normalized_key=unicodedata.normalize("NFC", key)
            if normalized_key in out: raise ValueError("duplicate JSON keys after Unicode NFC normalization")
            out[normalized_key]=normalize_json(item)
        return out
    if value is None or isinstance(value, (bool, int, float)): return value
    raise ValueError(f"unsupported JSON value type: {type(value).__name__}")


def canonical(value: Any) -> bytes:
    normalized=normalize_json(value)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def strict_json_loads(raw: str) -> Any:
    def no_duplicates(pairs):
        result={}
        for key, value in pairs:
            if key in result: raise ValueError(f"duplicate JSON key: {key}")
            result[key]=value
        return result
    return json.loads(raw, object_pairs_hook=no_duplicates, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {x}")))


def h(data: bytes, *, key: bytes | None = None) -> str:
    return hashlib.blake2b(data, digest_size=32, key=key or b"").hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def read_seed(path: Path) -> bytes:
    raw = path.read_bytes()
    if len(raw) != 32:
        raise ValueError(f"seed file must contain exactly 32 raw bytes; found {len(raw)}")
    if os.name != "nt" and (stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise PermissionError(f"seed permissions are too broad: {oct(stat.S_IMODE(path.stat().st_mode))}; require 0600")
    return raw


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        if os.name != "nt": os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def paths(state: Path) -> tuple[Path, Path, Path]:
    return state / "seed.key", state / "ledger.jsonl", state / "root.json"


def init_state(state: Path, import_seed: Path | None = None) -> dict[str, Any]:
    seed_path, ledger_path, root_path = paths(state)
    if any(p.exists() for p in (seed_path, ledger_path, root_path)):
        raise FileExistsError(f"state already initialized: {state}")
    state.mkdir(parents=True, exist_ok=True)
    if os.name != "nt": os.chmod(state, 0o700)
    seed = import_seed.read_bytes() if import_seed else secrets.token_bytes(32)
    if len(seed) != 32: raise ValueError("imported seed must contain exactly 32 raw bytes")
    atomic_write(seed_path, seed, 0o600)
    manifest = {
        "format": FORMAT, "digest": DIGEST, "created_at": utc_now(),
        "seed_commitment": h(b"CRYPTIC/SEED-COMMITMENT/v1\0" + seed),
        "routing_profile": ROUTING_PROFILE,
        "ledger": "ledger.jsonl", "merkle_root": None, "record_count": 0,
        "checkpoint_status": "local-unanchored"
    }
    atomic_write(root_path, canonical(manifest) + b"\n")
    atomic_write(ledger_path, b"")
    return manifest


def load_manifest(state: Path) -> dict[str, Any]:
    return json.loads(paths(state)[2].read_text("utf-8"))


def read_records(ledger_path: Path) -> list[dict[str, Any]]:
    records=[]
    if not ledger_path.exists(): raise FileNotFoundError(ledger_path)
    for n, line in enumerate(ledger_path.read_text("utf-8").splitlines(), 1):
        if not line.strip(): raise ValueError(f"blank ledger line {n}")
        try: record=strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as e: raise ValueError(f"invalid JSON at ledger line {n}: {e}") from e
        if canonical(record).decode("utf-8") != line:
            raise ValueError(f"non-canonical JSON encoding at ledger line {n}")
        records.append(record)
    return records


def record_core(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record[k] for k in ("sequence", "timestamp", "event_type", "payload", "previous_hash")}


def append_event(state: Path, event_type: str, payload: Any) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", event_type):
        raise ValueError("event_type must match [a-z0-9][a-z0-9._-]{0,127}")
    payload_bytes=canonical(payload)  # Reject duplicate keys, invalid values, and NaN/Infinity.
    if len(payload_bytes)>MAX_PAYLOAD_BYTES: raise ValueError(f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    seed_path, ledger_path, root_path = paths(state)
    seed=read_seed(seed_path); manifest=load_manifest(state); records=read_records(ledger_path)
    if manifest.get("record_count") != len(records): raise ValueError("root manifest record_count does not match ledger; verify/recover before append")
    prev=records[-1]["record_hash"] if records else ZERO
    core={"sequence":len(records), "timestamp":utc_now(), "event_type":event_type, "payload":payload, "previous_hash":prev}
    digest=h(b"CRYPTIC/LEDGER-RECORD/v1\0" + canonical(core))
    mac=h(b"CRYPTIC/LEDGER-MAC/v1\0" + bytes.fromhex(digest), key=seed)
    record={**core, "record_hash":digest, "authenticator":mac}
    with ledger_path.open("ab") as f:
        f.write(canonical(record)+b"\n"); f.flush(); os.fsync(f.fileno())
    manifest["record_count"]=len(records)+1
    manifest["merkle_root"]=None
    manifest["chain_tip"]=None
    manifest["checkpoint_status"]="local-unanchored"
    manifest.pop("root_updated_at", None)
    atomic_write(root_path, canonical(manifest)+b"\n")
    return {"sequence":record["sequence"], "record_hash":digest}


def merkle_root(hashes: list[str]) -> str:
    if not hashes: return h(b"CRYPTIC/MERKLE-EMPTY/v1\0")
    level=[bytes.fromhex(h(b"CRYPTIC/MERKLE-LEAF/v1\0"+bytes.fromhex(x))) for x in hashes]
    while len(level)>1:
        if len(level)%2: level.append(level[-1])
        level=[bytes.fromhex(h(b"CRYPTIC/MERKLE-NODE/v1\0"+level[i]+level[i+1])) for i in range(0,len(level),2)]
    return level[0].hex()


def verify_state(state: Path) -> dict[str, Any]:
    seed_path, ledger_path, root_path=paths(state)
    seed=read_seed(seed_path); manifest=load_manifest(state); records=read_records(ledger_path)
    commitment=h(b"CRYPTIC/SEED-COMMITMENT/v1\0"+seed)
    if commitment != manifest.get("seed_commitment"): raise ValueError("seed commitment mismatch")
    previous=ZERO; hashes=[]
    for i, rec in enumerate(records):
        required={"sequence","timestamp","event_type","payload","previous_hash","record_hash","authenticator"}
        if set(rec)!=required: raise ValueError(f"unexpected or missing fields at sequence {i}")
        if rec["sequence"]!=i: raise ValueError(f"sequence discontinuity at {i}")
        try:
            parsed_time=datetime.fromisoformat(rec["timestamp"].replace("Z", "+00:00"))
            if parsed_time.tzinfo is None or parsed_time.utcoffset().total_seconds()!=0: raise ValueError("timestamp must be UTC")
        except Exception as e: raise ValueError(f"invalid UTC timestamp at {i}") from e
        if rec["previous_hash"]!=previous: raise ValueError(f"previous-hash mismatch at {i}")
        digest=h(b"CRYPTIC/LEDGER-RECORD/v1\0"+canonical(record_core(rec)))
        if digest!=rec["record_hash"]: raise ValueError(f"record hash mismatch at {i}")
        mac=h(b"CRYPTIC/LEDGER-MAC/v1\0"+bytes.fromhex(digest),key=seed)
        if not secrets.compare_digest(mac,rec["authenticator"]): raise ValueError(f"record authenticator mismatch at {i}")
        previous=digest; hashes.append(digest)
    root=merkle_root(hashes)
    if manifest.get("record_count")!=len(records): raise ValueError("manifest record_count mismatch")
    expected=manifest.get("merkle_root")
    if expected is not None and expected!=root: raise ValueError("Merkle root mismatch")
    return {"valid":True,"records":len(records),"chain_tip":previous,"merkle_root":root,"seed_commitment":commitment,"checkpoint_status":manifest.get("checkpoint_status","unknown")}


def write_root(state: Path) -> dict[str, Any]:
    result=verify_state(state); manifest=load_manifest(state)
    manifest.update({"record_count":result["records"],"merkle_root":result["merkle_root"],"chain_tip":result["chain_tip"],"root_updated_at":utc_now(),"checkpoint_status":"local-unanchored"})
    atomic_write(paths(state)[2],canonical(manifest)+b"\n")
    return result

# Heuristic indicators only: review findings; do not auto-delete or auto-rewrite source.
AUDIT_PATTERNS=[
 ("dynamic-evaluation",re.compile(r"\b(eval|exec)\s*\(")),
 ("shell-execution",re.compile(r"\b(os\.system|subprocess\.(?:Popen|run|call))\s*\(")),
 ("shell-pipeline-download",re.compile(r"(?:curl|wget)[^\n|]*\|\s*(?:sh|bash)\b",re.I)),
 ("encoded-payload-decoding",re.compile(r"\b(base64|b64decode|marshal|pickle)\b")),
 ("credential-material",re.compile(r"(?i)(api[_-]?key|secret|password|mnemonic|seed[_-]?phrase)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
 ("dynamic-import",re.compile(r"\b(importlib\.import_module|__import__)\s*\(")),
 ("runtime-code-construction",re.compile(r"\b(compile)\s*\(")),
]


def audit_path(path: Path) -> list[dict[str, Any]]:
    findings=[]
    ignored={".git","node_modules",".venv","venv","__pycache__","dist","build"}
    files=[path] if path.is_file() else [p for p in path.rglob("*") if p.is_file() and not any(x in ignored for x in p.parts)]
    code_extensions={".py",".js",".jsx",".ts",".tsx",".mjs",".cjs",".sh",".ps1",".bat",".cmd",".go",".rs",".java",".c",".h",".cpp",".hpp",".json",".yaml",".yml",".toml"}
    for file in files:
        if file.resolve()==Path(__file__).resolve() or file.suffix.lower() not in code_extensions: continue
        try:
            if file.stat().st_size>2_000_000: continue
            text=file.read_text("utf-8")
        except (UnicodeDecodeError,OSError): continue
        for line_no,line in enumerate(text.splitlines(),1):
            if any(ch in line for ch in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069"):
                findings.append({"file":str(file),"line":line_no,"category":"bidirectional-control-character","excerpt":line.strip()[:240]})
            if any(ch in line for ch in "\u200b\u2060\ufeff"):
                findings.append({"file":str(file),"line":line_no,"category":"zero-width-control-character","excerpt":line.strip()[:240]})
            for label,pattern in AUDIT_PATTERNS:
                if pattern.search(line): findings.append({"file":str(file),"line":line_no,"category":label,"excerpt":line.strip()[:240]})
    return findings


def main() -> int:
    p=argparse.ArgumentParser(prog="cryptic-seed",description="CRYPTIC seed and Merkle ledger CLI")
    p.add_argument("--state",type=Path,default=Path(".cryptic"),help="local state directory (default: .cryptic)")
    sub=p.add_subparsers(dest="cmd",required=True)
    i=sub.add_parser("init"); i.add_argument("--seed-file",type=Path,help="import an existing 32-byte raw seed; never printed")
    a=sub.add_parser("append"); a.add_argument("event_type"); a.add_argument("--json",dest="payload_json",required=True,help="JSON payload")
    sub.add_parser("verify"); sub.add_parser("root")
    ex=sub.add_parser("export"); ex.add_argument("output",type=Path)
    au=sub.add_parser("audit"); au.add_argument("path",type=Path,nargs="?",default=Path("."))
    args=p.parse_args()
    try:
        if args.cmd=="init": result=init_state(args.state,args.seed_file); print(json.dumps({"initialized":True,"format":FORMAT,"seed_commitment":result["seed_commitment"],"state":str(args.state)}))
        elif args.cmd=="append":
            payload=strict_json_loads(args.payload_json); result=append_event(args.state,args.event_type,payload); print(json.dumps(result))
        elif args.cmd=="verify": print(json.dumps(verify_state(args.state),indent=2))
        elif args.cmd=="root": print(json.dumps(write_root(args.state),indent=2))
        elif args.cmd=="export":
            result=write_root(args.state); manifest=load_manifest(args.state); out={"manifest":manifest,"ledger":read_records(paths(args.state)[1])}
            atomic_write(args.output,canonical(out)+b"\n",0o644); print(json.dumps({"exported":str(args.output),"verification":result}))
        elif args.cmd=="audit":
            findings=audit_path(args.path); print(json.dumps({"findings":findings,"count":len(findings),"note":"heuristic only; absence of findings is not proof of safety"},indent=2)); return 1 if findings else 0
        return 0
    except Exception as e:
        print(f"cryptic-seed: error: {e}",file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
