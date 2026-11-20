"""Deterministic replay and data-quality analysis for raw observation journals."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .normalization import (
    NormalizationError,
    compare_chain_heads,
    normalize_journal_record,
)
from .observation_log import ObservationJournalError, audit_journal, read_records


REPLAY_SCHEMA = "cryptic.ingestion-replay.v1"


class ReplayError(ValueError):
    """Raised when replay policy or journal integrity cannot be satisfied."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def replay_journal(
    journal_path: str | Path,
    *,
    max_observation_skew_seconds: int = 15,
    max_height_delta: int = 1,
) -> dict[str, Any]:
    """Replay a verified journal without changing the journal or querying sources.

    The most recent observation from each source/network pair is used for
    cross-source comparison. All historical normalized observations remain
    represented in the replay output.
    """
    audit = audit_journal(journal_path)
    if not audit["valid"]:
        body = {
            "schema": REPLAY_SCHEMA,
            "valid": False,
            "quality_ok": False,
            "journal": audit,
            "summary": {
                "record_count": audit["record_count"],
                "normalized_count": 0,
                "comparison_count": 0,
                "issue_count": 1,
                "warning_count": 0,
            },
            "issues": [{"kind": "journal_integrity_failure", "detail": audit["error"]}],
            "warnings": [],
            "observations": [],
            "discrepancy_report": None,
        }
        return {**body, "replay_digest": _digest(body)}

    try:
        records = read_records(journal_path)
    except ObservationJournalError as exc:
        raise ReplayError("journal changed or failed verification during replay") from exc

    issues: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    normalized_rows: list[dict[str, Any]] = []
    latest_by_source_network: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {}
    seen_observations: dict[str, int] = {}
    previous_timestamp_by_source: dict[str, int] = {}

    for record in records:
        sequence = record["sequence"]
        source_id = record["source_id"]
        observation_id = record["observation_id"]
        first_seen = seen_observations.get(observation_id)
        if first_seen is not None:
            warnings.append({
                "kind": "duplicate_observation",
                "sequence": sequence,
                "first_sequence": first_seen,
                "observation_id": observation_id,
            })
        else:
            seen_observations[observation_id] = sequence

        prior_timestamp = previous_timestamp_by_source.get(source_id)
        if prior_timestamp is not None and record["observed_at"] < prior_timestamp:
            warnings.append({
                "kind": "source_timestamp_regression",
                "sequence": sequence,
                "source_id": source_id,
                "previous_observed_at": prior_timestamp,
                "observed_at": record["observed_at"],
            })
        previous_timestamp_by_source[source_id] = record["observed_at"]

        try:
            normalized = normalize_journal_record(record)
        except NormalizationError as exc:
            issues.append({
                "kind": "normalization_error",
                "sequence": sequence,
                "source_id": source_id,
                "detail": str(exc),
            })
            continue

        normalized_rows.append({"sequence": sequence, "observation": normalized})
        key = (normalized["network_identity"], source_id)
        current = latest_by_source_network.get(key)
        if current is None or (normalized["observed_at"], sequence) >= (
            current[1]["observed_at"], current[0]
        ):
            latest_by_source_network[key] = (sequence, normalized)

    comparison_inputs = [
        item[1] for _, item in sorted(
            latest_by_source_network.items(),
            key=lambda pair: (pair[0][0], pair[0][1]),
        )
    ]
    discrepancy_report = compare_chain_heads(
        comparison_inputs,
        max_observation_skew_seconds=max_observation_skew_seconds,
        max_height_delta=max_height_delta,
    )
    source_counts: dict[str, int] = defaultdict(int)
    for record in records:
        source_counts[record["source_id"]] += 1

    body = {
        "schema": REPLAY_SCHEMA,
        "valid": not issues,
        "quality_ok": not issues and not warnings and discrepancy_report["summary"]["consistent"],
        "journal": {
            "schema": audit["schema"],
            "record_count": audit["record_count"],
            "journal_root": audit["journal_root"],
        },
        "summary": {
            "record_count": len(records),
            "normalized_count": len(normalized_rows),
            "comparison_count": len(comparison_inputs),
            "source_count": len(source_counts),
            "source_record_counts": dict(sorted(source_counts.items())),
            "issue_count": len(issues),
            "warning_count": len(warnings),
            "discrepancy_count": discrepancy_report["summary"]["discrepancy_count"],
            "evidence_sufficient": discrepancy_report["summary"]["evidence_sufficient"],
        },
        "issues": issues,
        "warnings": warnings,
        "observations": normalized_rows,
        "discrepancy_report": discrepancy_report,
    }
    return {**body, "replay_digest": _digest(body)}
