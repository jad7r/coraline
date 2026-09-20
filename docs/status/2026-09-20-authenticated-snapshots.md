# Authenticated snapshot checkpoint — 2026-09-20

Implemented from clean `dfd92ed`, after inspecting the incident workspace, signed
manifest/Ed25519 primitives, audit chain, record/amendment stores, lifecycle,
sealing, projection/reporting, CLI verification, and existing locking/writes.
The [snapshot specification](../specs/authenticated-incident-snapshots-v1.md)
defines the security model, wire format, operator workflow, recovery and portable
verification. Snapshot signing reuses existing Ed25519 and canonical JSON helpers;
there is no competing incident verification algorithm in the CLI.

## Delivered boundaries

- Immutable, content-identified signed envelopes inventory all v1 authoritative
  sources and logical records. Generated graphs, PIRs, caches, keys and snapshot
  files themselves are excluded from incident-state authority.
- External private signing keys and separately pinned public verification keys.
  No embedded key can authorize a snapshot. One key per chain in v1.
- Sequence/predecessor ID/envelope-digest chain; optional independently retained
  expected tip detects deletion of that known tip.
- Creation holds the writer lock, checks existing core integrity and history,
  signs a stable inventory, and publishes without overwriting or appending audit.
- Separate structural/signature/chain/current-state results, read-only verification,
  snapshot health in core/CLI verify and doctor, historical and live reports.
- Snapshot-backed sealing captures the post-seal state and audit event. Failed
  final publication leaves a detectable requirement and supports explicit retry.
  Legacy incidents retain their previous sealing behavior.

## Adversarial review

Checked fixed source allowlists, snapshot ID/filename binding, cross-incident
identity, strict duplicate-key/nonfinite JSON parsing, signature domain separation,
unknown/wrong signer rejection, key substitution, path traversal, symlinks and
symlink loops, regular-file/size bounds, immutable publication, audit truncation,
record and amendment modification/deletion, chain removal/substitution, current
rollback, final-state mutation, CLI exit codes, private-key canaries, and separate
process creation. Snapshots never load a private key to verify.

Review corrected two defects before commit: unreadable/symlinked current sources
could be presented as ordinary historical differences, and symlink loops during
key-path resolution could escape as raw exceptions. Both now fail safely, with
regressions. Comparison validates and uses the same parsed signed document.

Tests use temporary incidents, generated ephemeral keys, restored environment
variables, and synthetic exception canaries. No real keychain, credentials,
provider, Redis, or external network is required by snapshot tests. A deterministic
mutation/permutation corpus covers malformed parsing and canonicalization without
adding a property-test dependency.

## Verification

- Focused incident/CLI suite: **223 passed**, including **89 new snapshot scenarios**.
- Full documented active suite: **595 passed, 1 skipped, 28 warnings,
  6 subtests passed**, 42.75 seconds. The existing optional GCS test remains skipped;
  warnings are existing Pydantic/Redis deprecations. The suite ran outside the
  previously identified sandbox thread/event-loop restriction.
- `compileall`, `pip check`, all three service environment-template shell syntax
  checks, and `git diff --check` passed. Pip reported a harmless unwritable cache
  warning before reporting no broken requirements.
- Tracked/new-file credential-format and artifact scan: no artifact paths or
  unresolved candidates. One unchanged archived Slack documentation placeholder
  matched the token-pattern scan and was confirmed as a placeholder without
  printing credential values. This scan is not proof against every credential format.
- Synthetic benchmark: 200 observations, 200 claims, 200 actions, 20 evidence
  records, three snapshots; creation approximately **0.44 s**, inventory **0.074 s**,
  snapshot size **195 KB**. The reproducible script uses temporary storage and real
  core APIs. Full creation verifies evidence bytes; inventory does not rehash blobs.

## Remaining limits and next milestone

No independent newest-head anchoring or trusted timestamp exists. A local chain
cannot detect deletion of its entire tail/all checkpoints without independently
retained expected material. The default public pin is a development convenience;
if an attacker replaces it alongside snapshots, it supplies no independent trust.
Snapshots authenticate semantic state, not JSON formatting or filesystem attributes.
Direct disk mutation remains possible and multi-file operations remain
nontransactional. Verification can observe concurrent writers and fail transiently.
Signing-key compromise, malicious authorized signers, compromised capture hosts,
filesystem denial of service and loss of every copy are outside the guarantee.

The best next milestone is independently retained snapshot anchors with verifiable
receipts and a durable expected-tip policy. The existing signed ID, sequence and
envelope digest support this without a format change. No anchor provider, network
service, transaction journal, graph feature or AI feature was implemented here.
