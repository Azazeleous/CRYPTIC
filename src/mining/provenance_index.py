"""Deterministic local index for CRYPTIC proof receipts and trophy manifests.

The index connects evidence; it does not create proof validity, network
acceptance, ownership, transferability, or monetary value.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .receipt_wallet import verify_receipt
from .trophy_manifest import verify_manifest

SCHEMA = "cryptic.provenance-index.v1"
_RECEIPT_ID = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _read_wallet(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], list[int]]:
    records: list[tuple[int, dict[str, Any]]] = []
    malformed: list[int] = []
    if not path.is_file():
        raise FileNotFoundError(f"wallet receipt archive not found: {path}")
    with path.open("rb") as stream:
        for number, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            try:
                item = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                malformed.append(number)
                continue
            if not isinstance(item, dict):
                malformed.append(number)
                continue
            records.append((number, item))
    return records, malformed


def _load_manifest(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
        return value if isinstance(value, dict) else None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def build_index(
    wallet_file: str | os.PathLike[str],
    manifest_dir: str | os.PathLike[str],
) -> dict[str, Any]:
    """Build a reproducible index from independently verified source artifacts."""
    wallet = Path(wallet_file).expanduser()
    manifests = Path(manifest_dir).expanduser()
    if not manifests.is_dir():
        raise FileNotFoundError(f"manifest directory not found: {manifests}")
    wallet_rows, malformed = _read_wallet(wallet)

    invalid_receipts: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    unique: dict[str, tuple[int, dict[str, Any]]] = {}

    for line, receipt in wallet_rows:
        try:
            valid = verify_receipt(receipt)
        except (AttributeError, KeyError, TypeError, ValueError):
            valid = False
        receipt_id = receipt.get("receipt_id")
        if not valid or not isinstance(receipt_id, str) or not _RECEIPT_ID.fullmatch(receipt_id):
            invalid_receipts.append({"line": line, "receipt_id": receipt_id})
            continue
        if receipt_id in unique:
            duplicates.append({"line": line, "receipt_id": receipt_id})
            continue
        unique[receipt_id] = (line, receipt)

    indexed: list[dict[str, Any]] = []
    missing_manifests: list[str] = []
    manifest_conflicts: list[str] = []
    referenced_files: set[str] = set()

    for receipt_id, (_, receipt) in sorted(unique.items()):
        filename = f"{receipt_id}.json"
        manifest_path = manifests / filename
        referenced_files.add(filename)
        if not manifest_path.exists():
            missing_manifests.append(receipt_id)
            continue
        manifest = _load_manifest(manifest_path)
        try:
            manifest_valid = manifest is not None and verify_manifest(manifest, receipt)
        except (AttributeError, KeyError, TypeError, ValueError):
            manifest_valid = False
        if not manifest_valid:
            manifest_conflicts.append(filename)
            continue

        identity = manifest["identity"]
        provenance = manifest["provenance"]
        integrity = manifest["integrity"]
        verification = manifest["verification"]
        indexed.append({
            "receipt_id": receipt_id,
            "work_id": identity["work_id"],
            "trophy_id": identity["trophy_id"],
            "manifest_hash": integrity["manifest_hash"],
            "wallet_id": provenance["wallet_id"],
            "ruleset_id": provenance["ruleset_id"],
            "accepted_at": provenance["accepted_at"],
            "algorithm": provenance["algorithm"],
            "proof_digest": provenance["proof_digest"],
            "receipt_integrity": verification["receipt_integrity"],
            "proof_verification": verification["proof_verification"],
            "network_acceptance": "not_claimed",
        })

    orphaned: list[str] = []
    if manifests.exists():
        for path in sorted(manifests.glob("*.json")):
            if path.name not in referenced_files:
                orphaned.append(path.name)

    checkpoint_payload = {
        "schema": "cryptic.provenance-checkpoint.v1",
        "records": indexed,
    }
    archive_root = hashlib.sha256(_canonical(checkpoint_payload)).hexdigest()
    issues = {
        "malformed_wallet_lines": malformed,
        "invalid_receipts": invalid_receipts,
        "duplicate_receipts": duplicates,
        "missing_manifests": missing_manifests,
        "manifest_conflicts": manifest_conflicts,
        "orphaned_manifests": orphaned,
    }
    valid = not any(issues.values())

    return {
        "schema": SCHEMA,
        "policy": {
            "source_of_truth": "verified_receipt_and_matching_manifest",
            "proof_scope": "local_sha256d_verification",
            "network_acceptance": "not_claimed",
            "valuation": None,
            "transferability": "not_defined",
        },
        "summary": {
            "wallet_records_read": len(wallet_rows) + len(malformed),
            "unique_valid_receipts": len(unique),
            "indexed_records": len(indexed),
            "issue_count": sum(len(value) for value in issues.values()),
            "valid": valid,
        },
        "checkpoint": {
            "algorithm": "SHA-256",
            "record_count": len(indexed),
            "archive_root": archive_root,
        },
        "records": indexed,
        "issues": issues,
    }


def verify_index(
    index: dict[str, Any],
    wallet_file: str | os.PathLike[str],
    manifest_dir: str | os.PathLike[str],
) -> bool:
    """Rebuild from source artifacts and require exact deterministic equality."""
    if not isinstance(index, dict) or index.get("schema") != SCHEMA:
        return False
    try:
        return index == build_index(wallet_file, manifest_dir)
    except (OSError, TypeError, ValueError, KeyError, AttributeError):
        return False


def export_index(index: dict[str, Any], destination: str | os.PathLike[str]) -> Path:
    """Write a canonical index to a new file; never overwrite an existing file."""
    if not isinstance(index, dict) or index.get("schema") != SCHEMA:
        raise ValueError("unsupported provenance index")
    summary = index.get("summary")
    records = index.get("records")
    checkpoint = index.get("checkpoint")
    if (not isinstance(summary, dict) or summary.get("valid") is not True
            or summary.get("issue_count") != 0 or not isinstance(records, list)):
        raise ValueError("refusing to export an index with source issues")
    expected_root = hashlib.sha256(_canonical({
        "schema": "cryptic.provenance-checkpoint.v1",
        "records": records,
    })).hexdigest()
    if (not isinstance(checkpoint, dict)
            or checkpoint.get("record_count") != len(records)
            or checkpoint.get("archive_root") != expected_root):
        raise ValueError("provenance checkpoint does not match indexed records")
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical(index) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def audit_index_file(
    index_file: str | os.PathLike[str],
    wallet_file: str | os.PathLike[str],
    manifest_dir: str | os.PathLike[str],
) -> dict[str, Any]:
    """Return a reproducible audit result for an exported index."""
    path = Path(index_file).expanduser()
    try:
        with path.open("r", encoding="utf-8") as stream:
            index = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"schema": "cryptic.provenance-index-audit.v1", "valid": False,
                "error": f"{type(exc).__name__}: {exc}"}

    valid = verify_index(index, wallet_file, manifest_dir)
    summary = index.get("summary") if isinstance(index, dict) else None
    checkpoint = index.get("checkpoint") if isinstance(index, dict) else None
    return {
        "schema": "cryptic.provenance-index-audit.v1",
        "valid": valid,
        "indexed_records": summary.get("indexed_records") if isinstance(summary, dict) else None,
        "archive_root": checkpoint.get("archive_root") if isinstance(checkpoint, dict) else None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and audit a local CRYPTIC provenance index")
    parser.add_argument("--wallet", required=True, help="receipt JSONL path")
    parser.add_argument("--manifests", required=True, help="portable trophy manifest directory")
    parser.add_argument("--output", help="optional new index JSON path")
    parser.add_argument("--verify", help="verify an existing index JSON file")
    args = parser.parse_args(argv)
    if args.verify:
        report = audit_index_file(args.verify, args.wallet, args.manifests)
    else:
        report = build_index(args.wallet, args.manifests)
        if args.output:
            if not report["summary"]["valid"]:
                parser.exit(2, "index export refused: source archive contains issues\n")
            try:
                export_index(report, args.output)
            except (OSError, TypeError, ValueError) as exc:
                parser.exit(2, f"index export error: {type(exc).__name__}: {exc}\n")
    print(json.dumps(report, sort_keys=True, indent=2))
    if "valid" in report:
        return 0 if report["valid"] else 2
    return 0 if report.get("summary", {}).get("valid", False) else 2


if __name__ == "__main__":
    raise SystemExit(main())
