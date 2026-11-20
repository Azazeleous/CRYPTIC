"""Deterministic chain-head normalization and cross-source discrepancy reports."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any


NORMALIZED_SCHEMA = "cryptic.normalized-chain-head.v1"
REPORT_SCHEMA = "cryptic.chain-discrepancy-report.v1"
_EVM_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
_SOLANA_HASH = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


class NormalizationError(ValueError):
    """Invalid source observation or comparison policy."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NormalizationError(f"{field} must be a non-negative integer")
    return value


def normalize_chain_observation(
    source_id: str,
    source_schema: str,
    observed_at: int,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one EVM or Solana adapter observation without guessing identity."""
    if not isinstance(source_id, str) or not source_id.strip():
        raise NormalizationError("source_id is required")
    if not isinstance(source_schema, str):
        raise NormalizationError("source_schema is required")
    observed_at = _nonnegative_int(observed_at, "observed_at")
    if not isinstance(payload, Mapping):
        raise NormalizationError("payload must be an object")

    if source_schema == "cryptic.evm-chain-observation.v1":
        chain_id = _nonnegative_int(payload.get("chain_id"), "chain_id")
        height = _nonnegative_int(payload.get("block_number"), "block_number")
        genesis_hash = payload.get("genesis_hash")
        head_hash = payload.get("block_hash")
        if not isinstance(genesis_hash, str) or not _EVM_HASH.fullmatch(genesis_hash):
            raise NormalizationError("EVM genesis_hash must be a 32-byte hex hash")
        if not isinstance(head_hash, str) or not _EVM_HASH.fullmatch(head_hash):
            raise NormalizationError("EVM block_hash must be a 32-byte hex hash")
        family = "evm"
        identity_body = {
            "family": family,
            "chain_id": chain_id,
            "genesis_hash": genesis_hash.lower(),
        }
    elif source_schema == "cryptic.solana-chain-observation.v1":
        genesis_hash = payload.get("genesis_hash")
        if not isinstance(genesis_hash, str) or not _SOLANA_HASH.fullmatch(genesis_hash):
            raise NormalizationError("Solana genesis_hash must be a base58-like 32-byte identifier")
        height = _nonnegative_int(payload.get("block_height"), "block_height")
        chain_id = None
        head_hash = None
        family = "solana"
        identity_body = {"family": family, "genesis_hash": genesis_hash}
    else:
        raise NormalizationError("unsupported source schema")

    network_identity = _digest(identity_body)
    return {
        "schema": NORMALIZED_SCHEMA,
        "source_id": source_id.strip(),
        "source_schema": source_schema,
        "network_family": family,
        "network_identity": network_identity,
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "height": height,
        "head_hash": head_hash.lower() if isinstance(head_hash, str) else None,
        "observed_at": observed_at,
    }


def normalize_journal_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one already-audited journal record containing exactly one item."""
    if not isinstance(record, Mapping):
        raise NormalizationError("journal record must be an object")
    if record.get("schema") != "cryptic.raw-observation.v1":
        raise NormalizationError("unsupported journal record schema")
    items = record.get("items")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], Mapping):
        raise NormalizationError("chain normalization requires exactly one object item")
    return normalize_chain_observation(
        record.get("source_id"),
        record.get("source_schema"),
        record.get("observed_at"),
        items[0],
    )


def compare_chain_heads(
    observations: Iterable[Mapping[str, Any]],
    *,
    max_observation_skew_seconds: int = 15,
    max_height_delta: int = 1,
) -> dict[str, Any]:
    """Compare independent source heads for identical, independently derived networks."""
    skew_limit = _nonnegative_int(max_observation_skew_seconds, "max_observation_skew_seconds")
    height_limit = _nonnegative_int(max_height_delta, "max_height_delta")
    if skew_limit > 3600:
        raise NormalizationError("max_observation_skew_seconds must not exceed 3600")
    if height_limit > 1_000_000:
        raise NormalizationError("max_height_delta must not exceed 1000000")

    rows: list[dict[str, Any]] = []
    source_keys: set[tuple[str, str]] = set()
    for observation in observations:
        if not isinstance(observation, Mapping) or observation.get("schema") != NORMALIZED_SCHEMA:
            raise NormalizationError("every input must be a normalized chain head")
        source_id = observation.get("source_id")
        family = observation.get("network_family")
        identity = observation.get("network_identity")
        height = _nonnegative_int(observation.get("height"), "height")
        observed_at = _nonnegative_int(observation.get("observed_at"), "observed_at")
        head_hash = observation.get("head_hash")
        if not isinstance(source_id, str) or not source_id:
            raise NormalizationError("normalized source_id is invalid")
        if family not in {"evm", "solana"} or not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity):
            raise NormalizationError("normalized network identity is invalid")
        if head_hash is not None and (
            not isinstance(head_hash, str) or not _EVM_HASH.fullmatch(head_hash)
        ):
            raise NormalizationError("normalized head_hash is invalid")
        key = (identity, source_id)
        if key in source_keys:
            raise NormalizationError("duplicate source_id for one network comparison")
        source_keys.add(key)
        rows.append(dict(observation))

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[row["network_identity"]].append(row)

    discrepancies: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    compared_groups = 0
    for identity in sorted(groups):
        group = sorted(groups[identity], key=lambda item: item["source_id"])
        if len(group) < 2:
            skipped.append({"network_identity": identity, "reason": "insufficient_independent_sources"})
            continue
        observed_times = [item["observed_at"] for item in group]
        skew = max(observed_times) - min(observed_times)
        if skew > skew_limit:
            skipped.append({
                "network_identity": identity,
                "reason": "observation_skew_exceeded",
                "observed_skew_seconds": skew,
            })
            continue
        compared_groups += 1
        heights = [item["height"] for item in group]
        minimum_height, maximum_height = min(heights), max(heights)
        source_ids = [item["source_id"] for item in group]
        if maximum_height - minimum_height > height_limit:
            discrepancies.append({
                "kind": "height_lag",
                "network_identity": identity,
                "source_ids": source_ids,
                "minimum_height": minimum_height,
                "maximum_height": maximum_height,
                "height_delta": maximum_height - minimum_height,
            })
        by_height: dict[int, set[str]] = defaultdict(set)
        for item in group:
            if item["head_hash"] is not None:
                by_height[item["height"]].add(item["head_hash"])
        for height, hashes in sorted(by_height.items()):
            if len(hashes) > 1:
                discrepancies.append({
                    "kind": "head_hash_conflict",
                    "network_identity": identity,
                    "height": height,
                    "source_ids": source_ids,
                    "distinct_head_hashes": sorted(hashes),
                })

    discrepancies.sort(key=lambda item: (
        item["network_identity"], item["kind"], item.get("height", -1)
    ))
    skipped.sort(key=lambda item: item["network_identity"])
    report_body = {
        "schema": REPORT_SCHEMA,
        "policy": {
            "max_observation_skew_seconds": skew_limit,
            "max_height_delta": height_limit,
            "identity_rule": "network_family_and_genesis_anchor",
        },
        "summary": {
            "input_observations": len(rows),
            "network_groups": len(groups),
            "compared_groups": compared_groups,
            "discrepancy_count": len(discrepancies),
            "skipped_group_count": len(skipped),
            "consistent": not discrepancies,
        },
        "discrepancies": discrepancies,
        "skipped_groups": skipped,
    }
    return {
        **report_body,
        "report_digest": _digest(report_body),
    }
