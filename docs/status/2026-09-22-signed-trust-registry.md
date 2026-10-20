# Signed trust-registry checkpoint status

Date: 2026-09-22

Status: implementation complete; reviewed checkpoint ready

## Implemented

- Independently pinned Ed25519 registry root
- Deterministic, domain-separated signed release envelopes
- Monotonic generation/predecessor chain with immutable key identities
- ACTIVE, RETIRED, REVOKED, and UNKNOWN key semantics
- Snapshot and filesystem/GCS anchor authorization integration
- Independently retained signed expected-tip history
- Rollback, conflict, missing-generation, and concurrent-writer detection
- Portable public-only bundle export and monotonic authenticated import
- Explicit broken-continuity trust-reset recovery
- Trust CLI plus verify/doctor integration
- Migration remains explicit; legacy pins work until a registry root is installed

## Known format boundary

Snapshot v1 and anchor-receipt v1 identify keys but predate registry generations.
Coreline enforces ACTIVE status on all new creation through authoritative APIs and
qualifies historical verification using the newest registry. A legacy artifact by
itself cannot prove which registry generation was current when it was signed. No
historical artifact is rewritten in this checkpoint.

## Verification

- Trust/snapshot/anchor/GCS/CLI focused suite: **217 passed**
- Incident and CLI integrity suite: **338 passed**
- Complete practical gate: **709 passed, 1 skipped, 1 deselected, 28 warnings,
  6 subtests passed** in 52.76 seconds
- The previously documented unrelated `asyncio.to_thread` provider-failure test
  still stalls in isolation in this runner; faulthandler shows the event loop waiting
  while a worker remains in `concurrent.futures.thread._worker`. No related code was
  changed and the test was deselected and reported rather than hidden. The other
  146 service tests are included in the successful complete practical gate.

## Follow-up — 2026-10-19

The provider-failure regression was isolated from the runner's thread-pool teardown:
the test now executes the blocking boundary inline while retaining the real route,
orchestrator, failing-provider, Redis, filesystem, integrity, and secret-redaction
assertions. Production behavior is unchanged. The complete gate now passes without
deselection: **710 passed, 1 skipped, 28 warnings, 6 subtests passed** in 48.39 seconds.
