# `interfaces/` — front-ends (no business logic)

Interfaces drive the one `core/`; they contain **no** business logic of their own. Per
[ADR-0002](../docs/adr/0002-ai-independent-platform.md) this demotes the Claude Desktop
skill from "the product" to *one interface*.

- `cli/` — the `coreline` operator CLI (primary interface; offline "3am" path). It
  supports declare, evidence intake, timeline, status, report, doctor, use, list, and
  close over `core.incident`. `verify --trusted` combines local evidence integrity
  checks with signer verification against a root-signed registry; use
  `--min-sequence` to enforce a known registry sequence floor.
  `snapshot` provides key provisioning, create/list/show, signature and chain
  verification, current-state comparison, and live checkpoint reports, all through
  authoritative core APIs. General `verify` and `doctor` include snapshot health.
  Configure `CORELINE_SNAPSHOT_VERIFY_KEY` for an independently protected public
  pin; explicit `--verify-key` (snapshot commands) or `--snapshot-verify-key`
  (general verify/seal) overrides it. Snapshot-backed sealing requires
  `lifecycle seal --snapshot-key` with an external private key. See the
  [snapshot guide](../docs/specs/authenticated-incident-snapshots-v1.md).
- `gui/` — optional Streamlit console over the same `core.incident` workspace.
- `skill/` — the Claude Desktop skill front-end (`SKILL.md` + templates), re-pointed to
  call `core/`. Remains a valid **zero-token assisted mode**.

> **Current status:** CLI and GUI are executable front ends. The current `SKILL.md`,
> `templates/`, and `scripts/build_timeline.py` still live at the repo root; relocating
> and reconciling them into `interfaces/` is later-phase work.
