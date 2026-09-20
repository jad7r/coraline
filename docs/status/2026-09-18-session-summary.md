# Coreline Session Summary - 2026-09-18

## Baseline

Branch: `main`. Working tree was clean before this session.
The initial baseline had 383 passed, 1 skipped, 17 warnings, and 6 subtests passed,
which supersedes the older August 15 count of 285 passing tests.

## CLI trust verification

Existing registry commands and local storage verification were already implemented.
Added the missing combined operator workflow:

```bash
.venv/bin/python -m interfaces.cli.coreline verify --trusted --min-sequence 2
.venv/bin/python -m interfaces.cli.coreline verify --all --trusted --root-verify /path/to/root.verify.json --min-sequence 2
```

- Authenticates the registry root seal and enforces the supplied sequence floor.
- Verifies the incident manifest's raw detached signature using its registry key.
- Rejects unknown/revoked signers alongside existing local integrity/storage failures.
- Supports explicit registry, seal, and pinned root public key paths.
- Plain verification reports signer trust as unchecked.
- Rejects conflicting incident selectors and trust options without `--trusted`.
- Documents that a zero sequence floor offers no rollback protection and local
  artifact checks do not attest cloud retention settings.

Verification logic lives in core; CLI code handles options and presentation.
Changes remain uncommitted.

## Validation

```bash
.venv/bin/python -m pytest core autonomous services lib interfaces/cli/tests interfaces/gui/tests -q
```

Result: **386 passed, 1 skipped, 17 warnings, 6 subtests passed** in 26.14 seconds.
The warnings concern Pydantic and Redis deprecations.
Added CLI coverage for the trusted workflow, missing/tampered/stale registries,
unknown/revoked signers, modified evidence, explicit trust paths, and invalid options.

## Next steps

Reconcile service documentation and environment examples around the shared
`CORELINE_` configuration boundary. Registry lifecycle commands and local artifact
verification already exist; do not restart the old Phase 1G1 checklist.
