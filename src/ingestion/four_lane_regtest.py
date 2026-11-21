"""Four-lane, deadline-bounded SHA-256d regtest.

This is a finite nonce-window worker and verification harness, not a digest
inverter. The coordinator owns the HCCGN-style monotonic deadline, independently
verifies every proposed winner, and emits exactly one accepted receipt.
"""
from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import threading
import time
from typing import Any

LANE_COUNT = 4
UINT32_MAX = (1 << 32) - 1
UINT256_MAX = (1 << 256) - 1


class RegtestError(ValueError):
    """Invalid regtest parameters or execution state."""


@dataclass(frozen=True, slots=True)
class LaneReport:
    lane_id: int
    role: str
    candidates_checked: int
    elapsed_ms: int
    hashes_per_second: float
    status: str
    proposed_nonce: int | None = None
    proposed_digest: str | None = None


def sha256d(header_prefix: bytes, nonce: int) -> bytes:
    """Bitcoin-style double SHA-256 of a 76-byte prefix plus LE uint32 nonce."""
    if not isinstance(header_prefix, bytes) or len(header_prefix) != 76:
        raise RegtestError("header_prefix_must_be_76_bytes")
    if isinstance(nonce, bool) or not isinstance(nonce, int) or not 0 <= nonce <= UINT32_MAX:
        raise RegtestError("nonce_out_of_uint32_range")
    header = header_prefix + nonce.to_bytes(4, "little")
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()


def _lane_worker(lane_id: int, header_prefix: bytes, nonce_start: int,
                 nonce_end: int, target: int, deadline: float,
                 stop: threading.Event) -> LaneReport:
    started = time.monotonic()
    checked = 0
    first = nonce_start + ((lane_id - nonce_start) % LANE_COUNT)
    for nonce in range(first, nonce_end + 1, LANE_COUNT):
        if stop.is_set():
            break
        if time.monotonic() >= deadline:
            elapsed = max(time.monotonic() - started, 1e-9)
            return LaneReport(lane_id, f"partition-{lane_id}", checked,
                              int(elapsed * 1000), checked / elapsed, "deadline")
        digest = sha256d(header_prefix, nonce)
        checked += 1
        # Bitcoin-style target interpretation: raw digest as a little-endian integer.
        if int.from_bytes(digest, "little") <= target:
            elapsed = max(time.monotonic() - started, 1e-9)
            return LaneReport(lane_id, f"partition-{lane_id}", checked,
                              int(elapsed * 1000), checked / elapsed,
                              "candidate", nonce, digest.hex())
    elapsed = max(time.monotonic() - started, 1e-9)
    status = "cancelled" if stop.is_set() else "exhausted"
    return LaneReport(lane_id, f"partition-{lane_id}", checked,
                      int(elapsed * 1000), checked / elapsed, status)


def run_four_lane_regtest(header_prefix: bytes, *, nonce_start: int,
                          nonce_end: int, target: int,
                          time_budget_seconds: float = 5.0,
                          experiment_commitment: str | None = None,
                          receipt_signing_secret_key: bytes | None = None,
                          receipt_signing_public_key: bytes | None = None) -> dict[str, Any]:
    """Run four disjoint nonce partitions with a central timed verifier.

    Three stages:
      1. REDUCE: assign the finite nonce interval to four disjoint residue lanes.
      2. SOLVE: lanes compute SHA-256d candidates under one monotonic deadline.
      3. CONVERGE: the center verifies one candidate and solidifies one receipt.
    """
    if not isinstance(header_prefix, bytes) or len(header_prefix) != 76:
        raise RegtestError("header_prefix_must_be_76_bytes")
    if experiment_commitment is not None:
        if not isinstance(experiment_commitment, str) or len(experiment_commitment) != 64:
            raise RegtestError("experiment_commitment_must_be_64_hex_characters")
        try:
            commitment_bytes = bytes.fromhex(experiment_commitment)
        except ValueError as exc:
            raise RegtestError("experiment_commitment_must_be_64_hex_characters") from exc
        if len(commitment_bytes) != 32 or header_prefix[36:68] != commitment_bytes:
            raise RegtestError("experiment_commitment_header_binding_mismatch")
    for name, value in (("nonce_start", nonce_start), ("nonce_end", nonce_end)):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT32_MAX:
            raise RegtestError(f"{name}_out_of_uint32_range")
    if (receipt_signing_secret_key is None) != (receipt_signing_public_key is None):
        raise RegtestError("receipt_signing_keypair_must_be_supplied_together")
    if receipt_signing_secret_key is not None:
        if not isinstance(receipt_signing_secret_key, bytes) or len(receipt_signing_secret_key) != 4032:
            raise RegtestError("ml_dsa_65_secret_key_length_invalid")
        if not isinstance(receipt_signing_public_key, bytes) or len(receipt_signing_public_key) != 1952:
            raise RegtestError("ml_dsa_65_public_key_length_invalid")
    if nonce_start > nonce_end:
        raise RegtestError("nonce_range_reversed")
    if isinstance(target, bool) or not isinstance(target, int) or not 0 <= target <= UINT256_MAX:
        raise RegtestError("target_out_of_uint256_range")
    if (isinstance(time_budget_seconds, bool)
            or not isinstance(time_budget_seconds, (int, float))
            or not math.isfinite(time_budget_seconds)
            or not 0 < time_budget_seconds <= 300):
        raise RegtestError("time_budget_must_be_finite_and_between_0_and_300_seconds")

    run_started = time.monotonic()
    deadline = run_started + float(time_budget_seconds)
    stop = threading.Event()
    stage_reduce_ms = (time.monotonic() - run_started) * 1000
    reports: dict[int, LaneReport] = {}
    winner: dict[str, Any] | None = None
    stage_solve_started = time.monotonic()

    executor = ThreadPoolExecutor(max_workers=LANE_COUNT, thread_name_prefix="cryptic-lane")
    futures = {
        executor.submit(_lane_worker, lane, header_prefix, nonce_start,
                        nonce_end, target, deadline, stop): lane
        for lane in range(LANE_COUNT)
    }
    try:
        pending = set(futures)
        while pending and winner is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                lane = futures[future]
                report = future.result()
                reports[lane] = report
                if report.status == "candidate":
                    nonce = report.proposed_nonce
                    if nonce is None:
                        raise RegtestError("candidate_missing_nonce")
                    # The center may not accept a result after the HCCGN deadline.
                    if time.monotonic() >= deadline:
                        break
                    verified = sha256d(header_prefix, nonce)
                    if verified.hex() != report.proposed_digest:
                        raise RegtestError("center_digest_reverification_failed")
                    if int.from_bytes(verified, "little") > target:
                        raise RegtestError("center_target_verification_failed")
                    winner = {
                        "lane_id": lane,
                        "nonce": nonce,
                        "digest": verified.hex(),
                        "target": f"{target:064x}",
                        "target_encoding": "raw_digest_little_endian_integer",
                    }
                    stop.set()
                    break
        if winner is None:
            stop.set()
        for future, lane in futures.items():
            if lane in reports:
                continue
            if future.done():
                reports[lane] = future.result()
            else:
                # A successfully cancelled future will never produce a worker report.
                # Record that terminal state immediately so every lane is represented.
                if future.cancel():
                    reports[lane] = LaneReport(
                        lane, f"partition-{lane}", 0, 0, 0.0, "cancelled"
                    )
        for future, lane in futures.items():
            if lane not in reports and not future.cancelled():
                try:
                    reports[lane] = future.result(timeout=max(0.05, time_budget_seconds))
                except Exception:
                    reports[lane] = LaneReport(lane, f"partition-{lane}", 0, 0, 0.0, "not_completed")
        # Defensive completeness invariant: report assembly below is total over all lanes.
        for lane in range(LANE_COUNT):
            reports.setdefault(
                lane, LaneReport(lane, f"partition-{lane}", 0, 0, 0.0, "not_completed")
            )
    finally:
        stop.set()
        executor.shutdown(wait=True, cancel_futures=True)

    stage_solve_ms = (time.monotonic() - stage_solve_started) * 1000
    stage_converge_started = time.monotonic()
    # A candidate is not accepted if independent verification or worker cleanup
    # carried execution beyond the caller's acceptance deadline.
    if winner is not None and time.monotonic() >= deadline:
        winner = None
    lane_rows = [asdict(reports[i]) for i in range(LANE_COUNT)]
    accepted = winner is not None
    receipt = None
    if accepted:
        receipt = {
            "schema": "cryptic.fgr-ice.regtest-receipt.v1",
            "accepted": True,
            "winner_lane": winner["lane_id"],
            "nonce": winner["nonce"],
            "digest": winner["digest"],
            "target": winner["target"],
            "target_encoding": winner["target_encoding"],
            "header_prefix_sha256": hashlib.sha256(header_prefix).hexdigest(),
            "experiment_commitment": experiment_commitment,
            "verification": "independent_sha256d_recomputation_passed",
        }
        if receipt_signing_secret_key is not None and receipt_signing_public_key is not None:
            from src.ingestion.pq_security import MLDSA65, RECEIPT_CONTEXT

            unsigned_bytes = json.dumps(
                receipt, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
            signature = MLDSA65.sign(
                receipt_signing_secret_key, unsigned_bytes, context=RECEIPT_CONTEXT
            )
            if not MLDSA65.verify(
                receipt_signing_public_key, unsigned_bytes, signature,
                context=RECEIPT_CONTEXT,
            ):
                raise RegtestError("ml_dsa_65_receipt_signature_self_verification_failed")
            receipt["signature"] = {
                "algorithm": "ML-DSA-65",
                "context": RECEIPT_CONTEXT.decode("ascii"),
                "public_key_hex": receipt_signing_public_key.hex(),
                "signature_hex": signature.hex(),
                "signed_payload": "receipt_fields_without_signature",
            }
    # Signing and self-verification are part of acceptance, not post-deadline
    # bookkeeping. Never emit an accepted receipt after that work crosses budget.
    if time.monotonic() >= deadline:
        accepted = False
        winner = None
        receipt = None
    stage_converge_ms = (time.monotonic() - stage_converge_started) * 1000
    elapsed_ms = (time.monotonic() - run_started) * 1000
    return {
        "schema": "cryptic.fgr-ice.four-lane-regtest.v1",
        "status": "accepted" if accepted else ("timed_out" if time.monotonic() >= deadline else "exhausted"),
        "process": ["REDUCE", "SOLVE", "CONVERGE"],
        "lane_count": LANE_COUNT,
        "lanes": lane_rows,
        "winner_count": 1 if accepted else 0,
        "winner": winner,
        "receipt": receipt,
        "metrics": {
            "nonce_start": nonce_start,
            "nonce_end": nonce_end,
            "domain_size": nonce_end - nonce_start + 1,
            "candidates_checked": sum(row["candidates_checked"] for row in lane_rows),
            "elapsed_ms": round(elapsed_ms, 3),
            "hashes_per_second": round(
                sum(row["candidates_checked"] for row in lane_rows) / max(elapsed_ms / 1000, 1e-9), 3
            ),
            "hccgn_timer": {
                "clock": "time.monotonic",
                "budget_seconds": float(time_budget_seconds),
                "deadline_enforced": True,
                "deadline_scope": "winner_verification_and_acceptance",
                "cleanup_may_extend_wall_clock": True,
                "stage_ms": {
                    "reduce": round(stage_reduce_ms, 3),
                    "solve": round(stage_solve_ms, 3),
                    "converge_and_receipt": round(stage_converge_ms, 3),
                },
            },
        },
    }
