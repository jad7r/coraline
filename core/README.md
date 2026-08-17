# `core/` — Coreline deterministic platform (system of record)

Per [ADR-0002](../docs/adr/0002-ai-independent-platform.md), `core/` is the
**deterministic execution engine and system of record.** No AI sits in its trust path;
every module here must function with **no LLM at all**. AI (see [`../ai/`](../ai/)) only
*adds* advisory reasoning on top, and its outputs are recorded — never authoritative.

Modules (each owns one platform responsibility):

| Package | Owns |
|---|---|
| `incident/` | local incident workspace, lifecycle metadata, reports, and audit wiring |
| `state/` | incident state machine (OPEN→…→SEALED); authoritative status |
| `evidence/` | evidence records + the integrity subsystem (`evidence/integrity/`) |
| `audit/` | append-only, tamper-evident audit log (records AI provenance) |
| `workflow/` | orchestration of a response across steps |
| `policy/` | guardrails / rules the engine enforces |
| `quality_gates/` | pre-closure and in-flight validation |
| `playbooks/` | playbook engine + the incident playbook content |

The connector framework lives at the repo-root [`../connectors/`](../connectors/).

> **Current status:** `incident/`, `evidence/`, and `storage/` contain executable,
> tested behavior. The remaining packages are placeholders for upcoming platform
> responsibilities.
