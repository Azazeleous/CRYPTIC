"""Reconcile a local receipt archive with portable trophy manifests.

This is a local provenance utility. It does not mine, submit work, issue or
transfer assets, or communicate with a network.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .receipt_wallet import verify_receipt
from .trophy_manifest import create_manifest, export_manifest, verify_manifest

_RECEIPT_ID = re.compile(r"^[0-9a-f]{64}$")


def _read_wallet(wallet_file: str | Path) -> tuple[list[tuple[int, dict[str, Any]]], list[int]]:
    """Read JSONL records, retaining line numbers and malformed-line locations."""
    records: list[tuple[int, dict[str, Any]]] = []
    malformed: list[int] = []
    path = Path(wallet_file).expanduser()
    if not path.exists():
        return records, malformed
    with path.open("rb") as stream:
        for line_number, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                malformed.append(line_number)
                continue
            if not isinstance(value, dict):
                malformed.append(line_number)
                continue
            records.append((line_number, value))
    return records, malformed


def reconcile_wallet(
    wallet_file: str | Path,
    manifest_dir: str | Path,
) -> dict[str, Any]:
    """Create missing manifests and reconcile all wallet receipts without overwrites.

    Repeated receipt IDs are counted as duplicates and exported only once.
    Existing manifest files are verified against their matching receipt and
    are never silently replaced. Invalid wallet lines and invalid receipts
    are reported rather than converted into trophies.
    """
    wallet_path = Path(wallet_file).expanduser()
    output_dir = Path(manifest_dir).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)

    records, malformed_lines = _read_wallet(wallet_path)
    unique: dict[str, tuple[int, dict[str, Any]]] = {}
    invalid_receipts: list[dict[str, Any]] = []
    duplicate_receipts: list[dict[str, Any]] = []

    for line_number, receipt in records:
        try:
            valid = verify_receipt(receipt)
        except (AttributeError, KeyError, TypeError, ValueError):
            valid = False
        receipt_id = receipt.get("receipt_id")
        if not valid or not isinstance(receipt_id, str) or not _RECEIPT_ID.fullmatch(receipt_id):
            invalid_receipts.append({"line": line_number, "receipt_id": receipt_id})
            continue
        if receipt_id in unique:
            duplicate_receipts.append({"line": line_number, "receipt_id": receipt_id})
            continue
        unique[receipt_id] = (line_number, receipt)

    generated: list[str] = []
    already_present: list[str] = []
    manifest_conflicts: list[dict[str, str]] = []
    verified_ids = set(unique)

    for receipt_id, (line_number, receipt) in unique.items():
        destination = output_dir / f"{receipt_id}.json"
        if destination.exists():
            try:
                with destination.open("r", encoding="utf-8") as stream:
                    existing = json.load(stream)
                if verify_manifest(existing, receipt):
                    already_present.append(receipt_id)
                else:
                    manifest_conflicts.append({
                        "receipt_id": receipt_id,
                        "path": str(destination),
                        "reason": "existing manifest failed verification against receipt",
                    })
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
                manifest_conflicts.append({
                    "receipt_id": receipt_id,
                    "path": str(destination),
                    "reason": "existing manifest could not be read or verified",
                })
            continue

        try:
            manifest = create_manifest(receipt)
            export_manifest(manifest, destination)
            generated.append(receipt_id)
        except (OSError, TypeError, ValueError, KeyError) as exc:
            manifest_conflicts.append({
                "receipt_id": receipt_id,
                "path": str(destination),
                "reason": f"manifest export failed: {type(exc).__name__}: {exc}",
            })

    orphaned_manifests: list[str] = []
    for candidate in sorted(output_dir.glob("*.json")):
        try:
            with candidate.open("r", encoding="utf-8") as stream:
                manifest = json.load(stream)
            provenance = manifest.get("provenance") if isinstance(manifest, dict) else None
            receipt_hash = provenance.get("receipt_hash") if isinstance(provenance, dict) else None
            if isinstance(receipt_hash, str) and receipt_hash not in verified_ids:
                orphaned_manifests.append(candidate.name)
        except (OSError, UnicodeError, json.JSONDecodeError):
            # A malformed file is surfaced as a conflict only when its expected
            # receipt filename was encountered above; otherwise it remains an orphan.
            orphaned_manifests.append(candidate.name)

    return {
        "schema": "cryptic.wallet-trophy-reconciliation.v1",
        "wallet_file": str(wallet_path),
        "manifest_directory": str(output_dir),
        "wallet_records_read": len(records) + len(malformed_lines),
        "unique_valid_receipts": len(unique),
        "generated_manifests": generated,
        "already_present_manifests": already_present,
        "duplicate_receipts": duplicate_receipts,
        "invalid_receipts": invalid_receipts,
        "malformed_wallet_lines": malformed_lines,
        "manifest_conflicts": manifest_conflicts,
        "orphaned_manifests": orphaned_manifests,
        "valid": not (
            malformed_lines or invalid_receipts or manifest_conflicts or orphaned_manifests
        ),
    }
