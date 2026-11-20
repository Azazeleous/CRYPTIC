"""Proof-of-work receipt and local trophy-wallet bridge.

This module records independently verified work as a portable receipt.
It does not mine, submit blocks, contact pools, transfer assets, or assign
monetary value. A receipt is locally verified until separate network evidence
is supplied and verified by a trusted full node.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from .sha256d import Candidate, verify_candidate

SCHEMA = "cryptic.pow-receipt.v1"
NETWORK_STATES = {"not_submitted", "accepted", "rejected"}


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_receipt(
    *,
    header: bytes,
    candidate: Candidate | dict[str, Any],
    wallet_id: str,
    ruleset_id: str,
    window_start: int,
    window_end: int,
    accepted_at: int | None = None,
    work_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a locally verified receipt within a governed time window."""
    if not wallet_id.strip():
        raise ValueError("wallet_id must not be empty")
    if not ruleset_id.strip():
        raise ValueError("ruleset_id must not be empty")
    if window_start < 0 or window_end <= window_start:
        raise ValueError("invalid governance window")
    timestamp = int(time.time()) if accepted_at is None else int(accepted_at)
    if not window_start <= timestamp < window_end:
        raise ValueError("receipt timestamp is outside the governance window")
    if not verify_candidate(header, candidate):
        raise ValueError("candidate failed independent SHA-256d verification")

    if isinstance(candidate, Candidate):
        nonce = candidate.nonce
        digest_hex = candidate.digest_hex.lower()
        hash_value = candidate.hash_value
        target = candidate.target
    else:
        nonce = int(candidate["nonce"])
        digest_hex = str(candidate["digest_hex"]).lower()
        hash_value = int(candidate["hash_value"])
        target = int(candidate["target"])

    body = {
        "schema": SCHEMA,
        "wallet_id": wallet_id,
        "ruleset_id": ruleset_id,
        "governance_window": {
            "start": int(window_start),
            "end_exclusive": int(window_end),
        },
        "accepted_at": timestamp,
        "work": {
            "header_hex": bytes(header).hex(),
            "nonce": nonce,
            "digest_hex": digest_hex,
            "hash_value_hex": f"{hash_value:064x}",
            "target_hex": f"{target:064x}",
            "algorithm": "SHA-256d",
            "header_bytes": 80,
        },
        "work_metrics": work_metrics or {},
        "verification": {
            "status": "locally_verified",
            "method": "independent_full_header_recomputation",
        },
        "network": {
            "status": "not_submitted",
            "evidence": None,
        },
    }
    receipt_id = _sha256(_canonical(body))
    return {**body, "receipt_id": receipt_id}


def verify_receipt(receipt: dict[str, Any]) -> bool:
    """Recompute receipt identity and the underlying candidate proof."""
    if receipt.get("schema") != SCHEMA:
        return False
    body = {key: value for key, value in receipt.items() if key != "receipt_id"}
    if _sha256(_canonical(body)) != receipt.get("receipt_id"):
        return False
    work = receipt.get("work", {})
    try:
        header = bytes.fromhex(work["header_hex"])
        candidate = {
            "nonce": int(work["nonce"]),
            "digest_hex": work["digest_hex"],
            "hash_value": int(work["hash_value_hex"], 16),
            "target": int(work["target_hex"], 16),
        }
        if not verify_candidate(header, candidate):
            return False
        window = receipt["governance_window"]
        if not int(window["start"]) <= int(receipt["accepted_at"]) < int(window["end_exclusive"]):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    return True


def append_to_wallet(receipt: dict[str, Any], wallet_file: str | os.PathLike[str]) -> Path:
    """Append a verified trophy receipt to a local JSONL wallet collection."""
    if not verify_receipt(receipt):
        raise ValueError("refusing to store an invalid receipt")
    path = Path(wallet_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_APPEND ensures each write is appended; a single encoded line is emitted.
    payload = _canonical(receipt) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        with os.fdopen(descriptor, "ab", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        raise
    return path


def verify_wallet(wallet_file: str | os.PathLike[str]) -> dict[str, Any]:
    """Audit every receipt in a local wallet file."""
    path = Path(wallet_file).expanduser()
    checked = 0
    invalid_lines: list[int] = []
    if not path.exists():
        return {"path": str(path), "checked": 0, "invalid_lines": [], "valid": True}
    with path.open("rb") as stream:
        for line_number, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            checked += 1
            try:
                item = json.loads(raw)
                if not verify_receipt(item):
                    invalid_lines.append(line_number)
            except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
                invalid_lines.append(line_number)
    return {
        "path": str(path),
        "checked": checked,
        "invalid_lines": invalid_lines,
        "valid": not invalid_lines,
    }
