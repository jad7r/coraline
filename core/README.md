# `core/` — Coreline deterministic platform (system of record)

Per [ADR-0002](../docs/adr/0002-ai-independent-platform.md), `core/` is the
**deterministic execution engine and system of record.** No AI sits in its trust path;
every module here must function with **no LLM at all**. AI (see [`../ai/`](../ai/)) only
*adds* advisory reasoning on top, and its outputs are recorded — never authoritative.

Modules (each owns one platform responsibility):

| Package | Owns |
|---|---|
| `state/` | incident state machine (DECLARED→…→CLOSED); authoritative status |
| `evidence/` | evidence records + the integrity subsystem (`evidence/integrity/`) |
| `audit/` | append-only, tamper-evident audit log (records AI provenance) |
| `workflow/` | orchestration of a response across steps |
| `policy/` | guardrails / rules the engine enforces |
| `quality_gates/` | pre-closure and in-flight validation |
| `playbooks/` | playbook engine + the incident playbook content |

The connector framework lives at the repo-root [`../connectors/`](../connectors/).

> **Phase 0 status:** skeleton only. Packages are empty placeholders except
> `evidence/integrity/`, into which the PyNaCl crypto core has been lifted. No behavior
> has been implemented yet — that is Phase 1.
