# Independent snapshot anchor checkpoint — 2026-09-20

Implemented from clean `62e56da`. The repository's existing Snapshot v1 format,
canonicalization, signing, state inventory, chain, current comparison, sealing,
locking, CLI, reporting, tests, specification, and benchmark were inspected before
design. The extension uses the existing complete-envelope snapshot digest and
trusted snapshot pin; Snapshot v1 bytes and semantics were not rewritten.

## Architecture and security result

Core remains authoritative for investigation semantics. Snapshots remain signed
checkpoints. Anchors receive only checkpoint identifiers/digests and create signed
acknowledgements. Neither providers nor receipts can mutate authoritative incident
state, audit, lifecycle, or snapshot content. AI and services remain outside this
trust path. CLI/reporting delegate to core.

The provider-neutral `SnapshotAnchor` contract has three operations: append an
acknowledgement, retrieve expected tip, and verify its ledger. The filesystem
reference stores append-only, no-overwrite signed receipts outside incident storage,
with per-incident advisory locks and hashed incident directory names. It requires
sequential snapshot anchoring. Duplicate identical operations are idempotent;
rollback, skipped sequence, branch, or conflict is rejected.

Each Ed25519 receipt domain-separates its canonical payload from snapshot signatures
and binds anchor/incident identity, snapshot ID/full-envelope/state digests, snapshot
signer and sequence/predecessor, anchor sequence/time metadata, and prior receipt
ID/digest. Independent registry pins map anchor identity to public key/provider/root
and policy. Receipt-supplied keys are never trusted. Private keys stay outside
Coreline home and never enter reports. Local receipt copies are non-authoritative
verification artifacts excluded from snapshot state.

Expected-tip relations are `MATCH`, `LOCAL_AHEAD_OF_EXPECTED`,
`LOCAL_BEHIND_EXPECTED`, `DIVERGED`, `LOCAL_SNAPSHOTS_MISSING`, and `UNANCHORED`.
`OPTIONAL` accepts absent/local-ahead state while rejecting any invalid existing
receipt or detected rollback. `REQUIRED` needs an online authenticated expected-tip
match. `REQUIRED_FOR_SEAL` becomes required at sealing. Both required policies
anchor the final post-seal snapshot; signing authorities are preflighted before the
lifecycle mutation. Provider/cache failures after final snapshot creation are
explicit and idempotently recoverable.

Offline results prove cached receipt authenticity and local snapshot matching under
the independent pin, while exposing that expected tip was not checked. Online
verification validates the external receipt ledger and freshness relation. Provider
unavailability and invalid provider data are separate: OPTIONAL may continue from
authentic cache when unavailable, but never when reachable data is invalid;
REQUIRED never downgrades or reports completion without an available expected tip.

## Adversarial findings and corrections

Testing demonstrated deletion of local S3/state rollback to S2 as
`LOCAL_BEHIND_EXPECTED` while the external ledger retains S3. It also covers total
local snapshot loss, divergent valid signed tails, external/cached receipt
modification/deletion/substitution, wrong/embedded keys, cross-incident reuse,
cross-protocol signatures, malformed inputs, duplicate keys through shared strict
parsing, sequential rollback/skip/fork attempts, stale cache, missing trust,
unavailable provider, cache-after-external failure, symlinks/path traversal,
malicious identifiers, concurrent duplicate append, read-only verification, and
synthetic secret canaries.

Review corrected three evidence-backed edge cases before commit:

- OPTIONAL initially treated a malformed reachable external ledger like ordinary
  provider unavailability. Invalid data now fails every policy; availability remains
  separately represented.
- REQUIRED could have relied on an authentic cached receipt after the entire
  external ledger disappeared. It now requires a returned external expected tip.
- REQUIRED policy sealing could create an unanchored final snapshot and return
  success. REQUIRED and REQUIRED_FOR_SEAL now both anchor/confirm the final tip.
- A reachable external ledger rolled back behind a newer authentic local cache was
  initially treated as a stale cache. Sequence/receipt cross-checking now treats a
  missing, older, or conflicting external tip as expected-tip rollback for all policies.

No provider error or malformed external value is exposed verbatim. Receipt/snapshot
signatures cannot cross protocols. Verification does not write. Snapshot and anchor
signing keys, registry roots, and signature blobs are absent from normal reports.

## Performance and verification

The reference provider revalidates prior history before each append. Each append and
full verification are O(n); building n receipts is deliberately O(n²) total rather
than trusting a mutable head index. With 100 receipts: creation 3.60 s total (36.0
ms mean), standalone verification 0.265 ms mean, expected-tip lookup 0.066 s, full
ledger verification 0.063 s. These are illustrative local results, not an SLA.

- Focused incident/CLI suite: **289 passed**.
- Focused snapshot+anchor selection: **155 passed**.
- Complete active suite: **661 passed, 1 skipped, 28 warnings, 6 subtests passed**
  in 51.29 seconds. The skip and Pydantic/Redis deprecations are pre-existing.
  One preceding full run hit the pre-existing single-sample Jira HMAC timing-ratio
  assertion (2.31 versus its 2.0 threshold); that test then passed three consecutive
  isolated runs and the final complete run. No unrelated timing test was changed.
- `compileall`, `pip check`, three service environment-template syntax checks, and
  `git diff --check` passed. Pip emitted only its existing unwritable-cache warning.
- Credential/artifact scan covered 312 tracked/new files: no runtime/key/database/
  cache artifacts or unresolved credential candidates. One unchanged archived Slack
  documentation placeholder matched the pattern and was confirmed without printing
  credential material. No benchmark output is committed.

## Remaining limitations and next milestone

The reference filesystem ledger is not inherently a separate security domain or
WORM store. If attacker control includes both incident and anchor storage, it can be
rolled back or destroyed. Registry pin protection is an operator/deployment duty.
Anchor and snapshot signing-key compromise, malicious authorized anchoring,
compromised hosts, availability attacks, trusted real-world time, multi-party
consensus, legal nonrepudiation, and true multi-file transactions remain outside v1.
Advisory filesystem locks are not promised across arbitrary network filesystems.
Receipt acknowledgement time remains signed metadata, not a trusted timestamp.

The recommended next milestone is one production-grade remote/WORM anchor adapter
with explicit capability declarations, durable receipt retrieval, and deployment
guidance for independently protecting the anchor registry pin. This should reuse the
v1 request/receipt contract rather than change incident or snapshot authority.
