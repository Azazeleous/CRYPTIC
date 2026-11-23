# SOS Supervised Process Boundary v1

## Purpose

The process supervisor runs a small set of trusted SOS operations in a fresh OS process. It gives the parent a real terminate/kill boundary and a monotonic execution deadline without granting extension packages arbitrary execution.

## Worker contract

- Uses Python multiprocessing with the spawn start method.
- Accepts one operation name and a bounded byte payload.
- Supports only sha256, text.stats, json.canonicalize, and diagnostic.pause.
- Rejects unknown operations, duplicate JSON keys, malformed UTF-8, invalid durations, oversized input, and oversized output.
- Returns a strict, bounded JSON response over a one-way pipe.
- The parent applies an absolute monotonic deadline and terminates, then kills, and joins the worker if the deadline expires.
- Worker response schema, base64 output, and output size are re-verified by the parent.

Input is capped at 1 MiB, output at 64 KiB, and operation deadlines at 50 ms through 10 seconds. The diagnostic pause operation is bounded to five seconds and exists to verify timeout/termination behavior.

## Security boundary

This is a real process boundary, not a privilege-separated OS sandbox. The worker runs with the same OS identity as its parent. It does not configure seccomp, namespaces, cgroups, Windows job objects, filesystem ACLs, or network ACLs. It cannot invoke extension artifacts, a shell, subprocesses, host files, or network APIs through the allowlisted operation table.

The parent deadline includes the worker lifecycle to the extent the parent can observe it. If process startup returns after the deadline, the worker is terminated immediately. A parent process blocked inside the operating system's process-start call cannot be asynchronously preempted by this Python layer.

## Verification

Source commit bc973e013535d7fd952d37b4a3bfdc20eb25ee1b passed:

- CRYPTIC CI run 45218707768 — 374 full-suite tests passed; six focused process-supervisor tests passed on Ubuntu and six on Windows.
- Mining-engine run 45218707845 — full suite and independent HCCGN conformance/benchmark steps are recorded in PR #40.
- GAIA local trophy run 45218708068 — passed.

This worker is not yet wired to execute extension code; extension artifacts remain opaque data.
