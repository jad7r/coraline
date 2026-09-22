# GCS snapshot anchor checkpoint status

Date: 2026-09-21

Status: implementation complete; remote-provider checkpoint ready

## Scope

- Provider-neutral anchor receipt contract retained
- New `gcs-v1` adapter using ambient ADC/WIF only
- Fixed sequence object ledger with create-only generation preconditions
- Full authenticated ledger read/list verification and expected-tip retrieval
- Provider type bound by signed receipt and independently pinned registry
- Explicit capabilities that do not claim application-verified retention or time
- CLI configuration, operator documentation, and hermetic fake-GCS tests

## Trust posture

GCS crosses a storage boundary only when independently administered. Bucket
retention lock, IAM, audit policy, and trusted-registry distribution remain
deployment controls verified outside Coreline. The adapter never sends incident
content, accepts credential-file paths, trusts receipt-provided keys, or mutates
authoritative incident records.

## Verification

Focused GCS, anchor-core, and anchor-CLI tests: **84 passed**.

Broader incident and CLI integrity suite: **307 passed**.

Complete collected suite: **680 tests**. The completed full gate excluding one
pre-existing service test produced **678 passed, 1 skipped, 1 deselected, 28
warnings, 6 subtests passed**. The deselected
`test_provider_failure_does_not_write_or_leak` consistently stalled in its existing
`asyncio.to_thread` provider-failure path in this runner, both in the full run and
in isolation. An attempted opaque-return workaround did not affect the runner stall
and was reverted; no unrelated service code is part of this checkpoint. The other
146 service tests passed. This limitation is recorded rather than represented as a
successful 680-test run.

`compileall`, `pip check`, three service environment-template syntax checks, and
`git diff --check` passed. A tracked/new-file scan covered 316 files: the only
artifact-name matches were the three intended empty environment templates, no
private-key markers were present, and reviewed assignment candidates were source,
tests, or archived documentation rather than credentials. No runtime receipt,
snapshot, key, database, cache, or benchmark output is included.

The hermetic 100-receipt in-memory benchmark measured 21.325 s total creation
(213.253 ms mean), 0.358 s expected-tip retrieval, and 0.363 s full-ledger
verification. These local runner figures are illustrative, not an SLA. Append is
O(n) and constructing n receipts is O(n²) because every append revalidates history.

## Remaining limits and next milestone

Coreline does not verify GCS bucket retention, IAM, organization policy, or audit
configuration. The registry pin still needs independently protected distribution.
Compromise of the cloud control plane, either signing key, the signing host, or an
unprotected registry remains outside this adapter's guarantees. Receipt time is not
trusted time, and provider availability remains separate from receipt validity.

The next milestone should be signed trust-registry release bundles with rotation
and recovery semantics, so anchor pins can be distributed and updated without
making incident storage or the receipt provider the source of trust.
