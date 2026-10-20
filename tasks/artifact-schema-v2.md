# Artifact schema v2 implementation checklist

Spec: `docs/specs/trust-bound-artifacts-v2.md`

Use red-first tests for each phase and keep v1 fixtures immutable.

## Phase 1 — registry release resolution

- [x] Resolve an exact authenticated release by generation, ID, digest, registry ID,
  and root key ID.
- [x] Classify a key at that historical release separately from its current status.
- [x] Reject release data not authenticated through the pinned local chain.

## Phase 2 — snapshot v2

- [x] Add v2 parsing, signing, IDs, and registry binding.
- [x] Emit v1 only in legacy-pin mode and v2 whenever a registry is installed.
- [x] Verify v1-to-v2 migration, forbid v2-to-v1 downgrade, and enforce
  nondecreasing bound generations.
- [x] Preserve current revocation behavior against the newest trusted release.

## Phase 3 — anchor receipt v2

- [ ] Add provider-neutral v2 request/receipt creation and verification.
- [ ] Implement identical behavior in filesystem and GCS adapters.
- [ ] Enforce one-way schema upgrade and nondecreasing bound generations.
- [ ] Preserve offline cached-receipt verification and expected-tip relations.

## Phase 4 — integration and documentation

- [ ] Integrate binding results into `verify`, `doctor`, sealing, reports, and CLI
  JSON/text output.
- [ ] Add portable mixed-chain fixtures and tamper/downgrade/rollback tests.
- [ ] Update operator migration guidance and the baseline test count.
- [ ] Run the complete regression gate with no deselections before review.

