"""Deterministic federation of independent local CRYPTIC provenance archives.

This module audits existing receipt/manifest archives. It does not create
proofs, perform mining, contact networks, issue assets, or assign value.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

from .provenance_index import build_index

SCHEMA = "cryptic.provenance-federation.v1"
_CHECKPOINT_SCHEMA = "cryptic.provenance-federation-checkpoint.v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value)


def _normalise_sources(sources: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(sources, (str, bytes, Mapping)):
        raise TypeError("sources must be an iterable of source objects")
    normalised: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in sources:
        if not isinstance(item, Mapping):
            raise TypeError("each source must be an object")
        source_id = item.get("source_id")
        wallet_file = item.get("wallet_file")
        manifest_dir = item.get("manifest_dir")
        expected = item.get("expected_archive_root")
        if not isinstance(source_id, str) or not source_id.strip():
            raise ValueError("every source requires a non-empty source_id")
        source_id = source_id.strip()
        if source_id in seen:
            raise ValueError(f"duplicate source_id: {source_id}")
        seen.add(source_id)
        if not isinstance(wallet_file, (str, os.PathLike)) or not str(wallet_file):
            raise ValueError(f"source {source_id} requires wallet_file")
        if not isinstance(manifest_dir, (str, os.PathLike)) or not str(manifest_dir):
            raise ValueError(f"source {source_id} requires manifest_dir")
        if expected is not None and not _is_sha256(expected):
            raise ValueError(f"source {source_id} expected_archive_root must be lowercase SHA-256")
        normalised.append({
            "source_id": source_id,
            "wallet_file": str(wallet_file),
            "manifest_dir": str(manifest_dir),
            "expected_archive_root": expected,
        })
    if not normalised:
        raise ValueError("at least one source archive is required")
    return sorted(normalised, key=lambda row: row["source_id"])


def _checkpoint_root(sources: list[dict[str, Any]],
                     records: list[dict[str, Any]],
                     issues: dict[str, Any]) -> str:
    payload = {
        "schema": _CHECKPOINT_SCHEMA,
        "sources": sources,
        "records": records,
        "issues": issues,
    }
    return hashlib.sha256(_canonical(payload)).hexdigest()


def build_federation(sources: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Rebuild source indexes and produce a deterministic federation audit.

    Each source object contains source_id, wallet_file, manifest_dir, and an
    optional expected_archive_root supplied by an independent archive owner.
    File paths are inputs only and are deliberately excluded from output.
    """
    inputs = _normalise_sources(sources)
    source_checkpoints: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    source_archive_issues: list[dict[str, Any]] = []
    checkpoint_mismatches: list[dict[str, str]] = []
    occurrences: dict[str, list[str]] = {}

    for source in inputs:
        source_id = source["source_id"]
        try:
            index = build_index(source["wallet_file"], source["manifest_dir"])
        except (OSError, TypeError, ValueError, KeyError, AttributeError) as exc:
            source_checkpoints.append({
                "source_id": source_id,
                "status": "unreadable",
                "archive_root": None,
                "indexed_records": 0,
                "issue_count": 1,
                "expected_archive_root": source["expected_archive_root"],
                "expected_checkpoint_matches": False if source["expected_archive_root"] else None,
            })
            source_archive_issues.append({
                "source_id": source_id,
                "kind": "source_unreadable",
                "error_type": type(exc).__name__,
            })
            continue

        checkpoint = index["checkpoint"]["archive_root"]
        expected = source["expected_archive_root"]
        matches = checkpoint == expected if expected is not None else None
        source_checkpoints.append({
            "source_id": source_id,
            "status": "valid" if index["summary"]["valid"] and matches is not False else "issues",
            "archive_root": checkpoint,
            "indexed_records": index["summary"]["indexed_records"],
            "issue_count": index["summary"]["issue_count"],
            "expected_archive_root": expected,
            "expected_checkpoint_matches": matches,
        })

        if not index["summary"]["valid"]:
            source_archive_issues.append({
                "source_id": source_id,
                "kind": "source_archive_has_issues",
                "details": index["issues"],
            })
        if matches is False:
            checkpoint_mismatches.append({
                "source_id": source_id,
                "expected_archive_root": expected,
                "observed_archive_root": checkpoint,
            })

        for record in index["records"]:
            row = {"source_id": source_id, **record}
            records.append(row)
            occurrences.setdefault(record["receipt_id"], []).append(source_id)

    records.sort(key=lambda row: (row["receipt_id"], row["source_id"]))
    cross_archive_duplicates = [
        {"receipt_id": receipt_id, "source_ids": sorted(source_ids)}
        for receipt_id, source_ids in sorted(occurrences.items())
        if len(source_ids) > 1
    ]
    issues = {
        "source_archive_issues": source_archive_issues,
        "checkpoint_mismatches": checkpoint_mismatches,
        "cross_archive_duplicates": cross_archive_duplicates,
    }
    valid = not any(issues.values())
    root = _checkpoint_root(source_checkpoints, records, issues)
    return {
        "schema": SCHEMA,
        "policy": {
            "source_of_truth": "independently_rebuilt_source_archive_indexes",
            "duplicate_policy": "preserve_each_occurrence_and_report_cross_archive_duplicates",
            "checkpoint_policy": "recompute_and_compare_optional_expected_archive_root",
            "signature_status": "not_implemented",
            "network_acceptance": "not_claimed",
            "valuation": None,
            "transferability": "not_defined",
        },
        "summary": {
            "source_count": len(source_checkpoints),
            "readable_sources": sum(row["archive_root"] is not None for row in source_checkpoints),
            "indexed_occurrences": len(records),
            "unique_receipt_ids": len(occurrences),
            "duplicate_receipt_ids": len(cross_archive_duplicates),
            "issue_count": (
                len(source_archive_issues)
                + len(checkpoint_mismatches)
                + len(cross_archive_duplicates)
            ),
            "valid": valid,
        },
        "checkpoint": {
            "algorithm": "SHA-256",
            "record_count": len(records),
            "federation_root": root,
        },
        "sources": source_checkpoints,
        "records": records,
        "issues": issues,
    }


def verify_federation(
    federation: dict[str, Any],
    sources: Iterable[Mapping[str, Any]],
) -> bool:
    """Rebuild from all source archives and require exact deterministic equality."""
    if not isinstance(federation, dict) or federation.get("schema") != SCHEMA:
        return False
    try:
        return federation == build_federation(sources)
    except (OSError, TypeError, ValueError, KeyError, AttributeError):
        return False


def export_federation(
    federation: dict[str, Any], destination: str | os.PathLike[str]
) -> Path:
    """Export only a clean federation, using exclusive create and mode 0600."""
    if not isinstance(federation, dict) or federation.get("schema") != SCHEMA:
        raise ValueError("unsupported provenance federation")
    summary = federation.get("summary")
    sources = federation.get("sources")
    records = federation.get("records")
    issues = federation.get("issues")
    checkpoint = federation.get("checkpoint")
    if (not isinstance(summary, dict) or summary.get("valid") is not True
            or summary.get("issue_count") != 0
            or not isinstance(sources, list)
            or not isinstance(records, list)
            or not isinstance(issues, dict)
            or any(bool(value) for value in issues.values())):
        raise ValueError("refusing to export a federation with source issues")
    if any(not isinstance(source, dict) or source.get("status") != "valid"
           for source in sources):
        raise ValueError("refusing to export a federation with non-valid sources")
    if (summary.get("source_count") != len(sources)
            or summary.get("indexed_occurrences") != len(records)
            or summary.get("readable_sources") != len(sources)):
        raise ValueError("federation summary does not match its contents")
    expected_root = _checkpoint_root(sources, records, issues)
    if (not isinstance(checkpoint, dict)
            or checkpoint.get("algorithm") != "SHA-256"
            or checkpoint.get("record_count") != len(records)
            or checkpoint.get("federation_root") != expected_root):
        raise ValueError("federation checkpoint does not match its contents")
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(_canonical(federation) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return path


def audit_federation_file(
    federation_file: str | os.PathLike[str],
    sources: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Audit an exported federation against the live source archives."""
    path = Path(federation_file).expanduser()
    try:
        with path.open("r", encoding="utf-8") as stream:
            federation = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {
            "schema": "cryptic.provenance-federation-audit.v1",
            "valid": False,
            "error_type": type(exc).__name__,
        }
    valid = verify_federation(federation, sources)
    checkpoint = federation.get("checkpoint") if isinstance(federation, dict) else None
    summary = federation.get("summary") if isinstance(federation, dict) else None
    return {
        "schema": "cryptic.provenance-federation-audit.v1",
        "valid": valid,
        "source_count": summary.get("source_count") if isinstance(summary, dict) else None,
        "federation_root": checkpoint.get("federation_root") if isinstance(checkpoint, dict) else None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build or audit a local CRYPTIC provenance federation"
    )
    parser.add_argument("--sources", required=True,
                        help="JSON file containing a sources array")
    parser.add_argument("--output", help="optional new federation JSON path")
    parser.add_argument("--verify", help="audit an existing federation JSON file")
    args = parser.parse_args(argv)
    try:
        with Path(args.sources).expanduser().open("r", encoding="utf-8") as stream:
            config = json.load(stream)
        if not isinstance(config, dict) or not isinstance(config.get("sources"), list):
            raise ValueError("source configuration must contain a sources array")
        if args.verify:
            report = audit_federation_file(args.verify, config["sources"])
        else:
            report = build_federation(config["sources"])
            if args.output:
                if not report["summary"]["valid"]:
                    parser.exit(2, "federation export refused: source archives contain issues\n")
                export_federation(report, args.output)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        parser.exit(2, f"federation error: {type(exc).__name__}: {exc}\n")
    print(json.dumps(report, sort_keys=True, indent=2))
    if "valid" in report:
        return 0 if report["valid"] else 2
    return 0 if report.get("summary", {}).get("valid", False) else 2


if __name__ == "__main__":
    raise SystemExit(main())
