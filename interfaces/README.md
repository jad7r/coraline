# `interfaces/` — front-ends (no business logic)

Interfaces drive the one `core/`; they contain **no** business logic of their own. Per
[ADR-0002](../docs/adr/0002-ai-independent-platform.md) this demotes the Claude Desktop
skill from "the product" to *one interface*.

- `cli/` — the `coreline` operator CLI (primary interface; offline "3am" path). Will absorb
  the Gen-3 `coreline.py` from the fossil.
- `gui/` — optional desktop console (later).
- `skill/` — the Claude Desktop skill front-end (`SKILL.md` + templates), re-pointed to
  call `core/`. Remains a valid **zero-token assisted mode**.

> **Phase 0 status:** skeleton only. The current `SKILL.md`, `templates/`, and
> `scripts/build_timeline.py` still live at the repo root; relocating/reconciling them
> into `interfaces/` is later-phase work, not Phase 0.
