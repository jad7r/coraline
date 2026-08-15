# Coreline — Starting Point for 2026-08-15

Purpose: tomorrow morning should start from this machine's actual state, not the older
status notes. The active workspace is:

`/home/ubu/working_dir/coreline`

## Current Machine State

- Coreline has been moved out of the confusing nested layout. Use this repo root only.
- The working tree has been scrubbed of old project-name references.
- Git is initialized on branch `main`, but there are no commits yet in this copied tree.
- No local virtual environment exists in this tree right now.
- `python3 scripts/build_timeline.py --help` runs successfully with stdlib only.
- `python3 -m pytest core/ -q` does not run yet because `pytest` is not installed.

## Current Product Direction

ADR-0002 is the controlling direction: Coreline is an AI-independent incident-response
platform. LLMs and skills are front ends; the deterministic evidence engine is the system
of record.

The evidence integrity spine present in this tree includes:

- SHA-256 hashing and canonical manifests
- hash-linked custody records
- detached Ed25519 seals with subject/domain separation
- trusted signer registry
- root-signed registry verification
- registry rollback enforcement with signed `sequence` plus verifier `min_sequence`
- write-only storage abstraction with local and GCS-oriented backends

The v3 skill and templates remain useful as an operator-facing workflow layer, but the
build path should prioritize the deterministic core first.

## Important Reconciliation

Older status notes mention prior commits, a populated `.venv`, and green test counts.
Those refer to a previous source state. In this copied/scrubbed tree:

- Git history is not present.
- `.venv` is not present.
- Tests have not been re-run successfully on this machine because dependencies are absent.

Treat tomorrow as a fresh local baseline stabilization pass before feature acceleration.

## First Hour Tomorrow

1. Create the local dev environment:

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements-services.txt
   ```

2. Run the core test suite:

   ```bash
   .venv/bin/python -m pytest core/ -q
   ```

3. If green, make the first local baseline commit:

   ```bash
   git add .
   git commit -m "Establish Coreline baseline"
   ```

4. If tests fail, fix only environment or rename fallout first. Do not begin new feature work
   until the baseline is green.

## Acceleration Backlog

Start after the baseline commit:

1. Platform cleanup: remove or quarantine orphaned GUI/service code that is outside the
   ADR-0002 product direction.
2. Core CLI: expose the evidence spine through a minimal operator CLI.
3. Incident state: wire lifecycle state transitions into the deterministic core.
4. Evidence workflow: declare incident, add evidence, seal manifest, verify chain.
5. Registry workflow: create/update signer registry, bump sequence, seal with root key,
   verify with a floor.
6. Storage workflow: write evidence artifacts through the storage abstraction.
7. Skill packaging: package only the skill files and scripts needed for operator workflow,
   not the whole repo.
8. Documentation cleanup: make README, architecture, and task docs agree on the current
   platform direction.

## Next Decision

Before coding new features, decide whether tomorrow's first milestone is:

- **CLI-first:** make Coreline usable locally as a deterministic incident/evidence tool.
- **Cleanup-first:** remove non-directional code so the repo has one coherent product shape.

Recommendation: CLI-first, but only after the baseline tests are green. A small usable CLI
will reveal which cleanup matters and which old code can be ignored or deleted.

