# Coreline Session Summary - 2026-08-15

Active workspace:

`/home/ubu/working_dir/coreline`

## Checkpoints

- `96970c6 Establish Coreline baseline`
- `d5cb58b Add Coreline operator CLI flow`
- `ad70548 Promote incident workspace into core`

## Current Baseline

The local virtual environment exists at `.venv/`.

Baseline gate:

```bash
.venv/bin/python -m pytest core autonomous services lib interfaces/cli/tests interfaces/gui/tests -q
```

Latest result:

```text
285 passed, 1 skipped, 17 warnings, 6 subtests passed
```

Scrub check: search the working tree for the previous project name while excluding
`.git/`, `.venv/`, bytecode, and cache directories. Expected result: no matches.

## What Changed

- Added CLI operator commands: `doctor`, `use`, and `close`.
- Replaced the old stylized CLI banner with Coreline branding.
- Locked evidence intake after incident closure.
- Updated Slack orchestrator `.env.template` to use `CORELINE_` names and
  `coreline:incident:created`.
- Promoted incident workspace logic from `interfaces/cli/workspace.py` into
  `core/incident/workspace.py`.
- Left `interfaces/cli/workspace.py` as a compatibility shim.
- Moved workspace domain tests under `core/incident/tests`.
- Updated README and interface docs to match the current local-first architecture.

## Tomorrow Starting Point

Start from a clean tree on branch `main` and verify the baseline before new work:

```bash
cd /home/ubu/working_dir/coreline
git status --short
.venv/bin/python -m pytest core autonomous services lib interfaces/cli/tests interfaces/gui/tests -q
```

Recommended next stage: keep the CLI-first path and add the next useful operator workflow
around registry/storage verification, then reconcile service docs around the same
`CORELINE_` configuration boundary.
