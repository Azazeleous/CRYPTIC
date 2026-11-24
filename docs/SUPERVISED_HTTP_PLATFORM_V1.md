# Supervised HTTP Platform Verification v1

The supervised whole-request HTTP transport uses a prestarted multiprocessing spawn worker for DNS, TCP, TLS, HTTP headers, and response-body reads. The parent enforces one absolute monotonic deadline, caps request and response sizes, denies redirects, and terminates/poisons the worker if the deadline expires after dispatch.

PR #39 adds a focused CI matrix on ubuntu-latest and windows-latest using Python 3.12. The platform suite verifies:

- spawn worker startup and complete request/response handling;
- redirect denial and response-size bounds;
- waiter deadline behavior without aborting the active request;
- truncated chunked responses;
- slow-trickle response termination at the absolute deadline;
- poisoned worker behavior after timeout;
- worker process reaping and shared-memory unlink on close.

Source commit 8f7f017f36032847c17e915dba7dbfa3d7b2642e passed:

- CRYPTIC CI run 45217841723 — 369 full-suite tests; 8 focused transport tests passed on Ubuntu and 8 on Windows.
- Mining-engine run 45217841750 — 369 tests; independent Go HCCGN conformance and bounded HCCGN/SHA-256d benchmark steps passed.
- GAIA local trophy run 45217841610 — passed.

These are GitHub-hosted runner results. They verify the spawn/cleanup contract on those runners, not live provider interoperability, production endpoint availability, or target-device performance.
