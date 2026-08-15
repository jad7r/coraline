# ADR-0003 — Revive Archived Services & Autonomous Engine

- **Status:** Proposed (pending product-owner sign-off)
- **Date:** 2026-08-04
- **Deciders:** Product owner (J. Dellinger)
- **Supersedes (in part):** [ADR-0002](0002-ai-independent-platform.md) — reverses its
  §Non-goals for the microservice mesh and the autonomous agent.
- **Driver:** Product-owner directive ("bring Coreline fully operational — desktop, CLI, and
  MCP capabilities") on 2026-08-04.

## Context

ADR-0002 (Accepted, 2026-07-06) deliberately archived, as explicit **Non-goals**:

- the always-on microservice **mesh** (FastAPI webhook daemons, Redis, Docker/Cloud Run), and
- the **autonomous agent** (conflicts with human-in-the-loop; AI is advisory only).

Those components physically live in `archive/experimental/` and are imported by nothing in
the running product (`core/`, `interfaces/`, `ai/`). The product owner has now decided to
bring them back into active scope.

## Decision

Reverse the ADR-0002 Non-goals for the mesh and the autonomous agent. Move the following
from `archive/experimental/` back into the active tree and re-verify each:

| Component | Real archived path | Stack it drags back in |
|-----------|--------------------|------------------------|
| Autonomous engine | `brain-autonomous/` (1,184 LOC) | agent orchestrator + recommendation engine |
| Grafana webhook | `grafana-webhook/` (149 LOC) | Flask always-on receiver |
| Slack orchestrator | `slack-orchestrator/` (1,850 LOC) | FastAPI + Redis + Docker |
| Jira webhook listener | `jira-webhook-listener/` (3,146 LOC) | FastAPI + Redis + Docker |
| Brain service | `coreline-brain-service/` (1,380 LOC) | FastAPI + Redis + Docker |

## Explicitly NOT in this ADR (no code exists to "revive")

The originating request also named a FastMCP server, a VirusTotal lookup, a MISP client,
and an `enclave_adapter` signing layer. **None of these exist in the repo or its history** —
they are net-new builds, not revivals, and are out of scope here. If wanted, they get their
own ADR + plan.

## Consequences (accepted by taking this decision)

- Re-introduces standing infrastructure: FastAPI, uvicorn, Redis, Docker — the operational
  weight ADR-0002 and its predecessors were built to shed.
- Re-introduces standing credentials/tokens (Slack bot, Jira, Redis) and always-on network
  surface, each of which is a new attack surface to secure and monitor.
- The autonomous agent reintroduces the human-in-the-loop tension ADR-0002 §2 resolved; AI
  output that previously could only ever be advisory can now drive action autonomously.
- All revived code was never production-validated → **re-verify, do not trust**. Two
  collection errors already exist in `jira-webhook-listener/tests/`.

## Follow-up

A phased un-archival plan (below / in the task tracker) will move one component at a time,
each behind its own PR with tests green, so any single revival can be reverted in isolation.
