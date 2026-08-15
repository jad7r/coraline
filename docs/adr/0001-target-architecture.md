# ADR-0001 — Target Architecture: v3 Skill + Revived Local Toolkit

- **Status:** SUPERSEDED by [ADR-0002](0002-ai-independent-platform.md) (2026-07-06)
- **Date:** 2026-07-06
- **Deciders:** Product owner (J. Dellinger) + Staff Architect review
- **Supersedes:** the implicit "v3 skill only" direction of the 2026-06-26 pivot
- **Context doc:** `ASSESSMENT.md` (full repository assessment, incl. `CORELINE_OLD_DESIGN/`)

> **Superseded same day.** This ADR framed the toolkit as a *helper for Claude*. The
> product owner corrected the vision: Coreline is an **AI-independent platform** and the
> system of record; the LLM is a replaceable plugin. The hybrid direction below is
> still broadly correct but is subsumed and re-framed by ADR-0002. Retained for history.

## Context

Coreline has been through five generations, each stripping the prior one down to escape
operational weight (see `ASSESSMENT.md` §0):

1. v1 web app → 2. v2 GCP microservice mesh → 3. "Coreline Lite" local CLI →
4. single-file Tkinter GUI → 5. v3 Claude Desktop skill.

The 2026-06-26 pivot to the v3 skill was driven by a reasonable fear of operational tax,
but it over-corrected: it discarded **built, valuable, low-tax capability** — an offline
operator CLI, incident state tracking, evidence hashing + WORM, a pre-closure quality
gate, PIR generation, and a library of six detailed incident playbooks. All of that
survives in `CORELINE_OLD_DESIGN/`.

Critically, the operational tax that motivated every simplification lives in the
**always-on microservice mesh** (webhook daemons, Redis, Cloud Run, a standing Slack bot
token, an autonomous agent) — **not** in the local CLI/tools/playbooks, which are plain
offline Python of the same shape as the already-embraced `build_timeline.py`.

## Decision

Adopt a **hybrid architecture**:

- **Keep the v3 skill** as the orchestration layer. Claude drives Slack / Jira / Google
  Drive through the operator's **own OAuth connectors** — no standing service tokens.
- **Revive a local, offline Python toolkit** (from Gen 2/3) for the deterministic,
  stateful, and forensic work Claude should not do free-form:
  - `coreline.py` operator CLI + the six-state incident state machine
  - evidence **SHA-256 hashing + WORM** write (the evidence-integrity engine)
  - the pre-closure **quality gate**
  - **PIR generation** (`coreline-brain.py` + `brain/`)
  - `build_timeline.py` (already present) stays the reference for this layer's shape
- **Adopt the six incident playbooks** + supporting docs (breach-notification matrix,
  comms templates, contact list, evidence-collection guide) as product content.

Everything in this toolkit MUST remain **local, offline, no-daemon, no standing token** —
the `build_timeline.py` bar.

## Explicitly NOT re-adopted (kept in the fossil layer)

- The always-on microservice mesh: `jira-webhook-listener`, `slack-orchestrator`,
  `coreline-brain-service`, Redis, Cloud Run/Docker, Terraform infra.
- The **autonomous brain agent** — conflicts with the human-in-the-loop principle.
- The broad standing **Slack bot token** model.

## Deferred (revisit later, not now)

- The **secure enclave** (PyNaCl client-side encryption + WordPress portal). Good crypto,
  but beta; its own docs state it needs a third-party security audit, and the WordPress
  portal is a large new attack surface. Reconsider once the core toolkit is restored and
  if an incident genuinely requires cryptographic evidence sealing beyond WORM.

## Consequences

**Positive**
- Restores the "3am offline" spine v3 lacks, and fixes the false-WORM integrity defect
  (`ASSESSMENT.md` C2) with code that already exists.
- No new operational tax: nothing to deploy, no daemon, no standing token.
- The playbooks become usable immediately and are architecture-agnostic.

**Costs / risks**
- Revived Gen-2/3 code was self-reported "complete" but **never validated in production**
  (empty data files; partial test suites). It must be re-verified, not trusted.
- Two execution surfaces (skill + local CLI) must stay coherent — the skill should hand
  work to the CLI the way it already hands work to `build_timeline.py`.
- The repo has **no version control**; git must be initialized as a safety net before any
  file moves.

## Follow-up (see `ASSESSMENT.md` §8 roadmap)

M1 repo truth + `git init`; M2 contain security defects; M3 salvage playbooks + evidence
integrity; M4 prove one skill flow end-to-end; M5 timeline manifest + first tests;
M6 re-adopt state machine + quality gate; M7 compliance decisions; M8 remaining flows.
