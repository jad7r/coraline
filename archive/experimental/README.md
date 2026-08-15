# Experimental / archived — NOT part of Coreline Lite

Everything in this directory is **quarantined**. It is **not required** to run
Coreline, is **not imported** by the CLI (`coreline.py`), the GUI (`coreline_gui/`), the
shared library (`lib/`), the tools (`tools/`), or the local PIR generator
(`coreline-brain.py`). It is kept only for reference/history.

## Why it was moved here

Coreline Lite is a lightweight Python incident-operations tool: a single
operator-facing CLI, an optional desktop GUI, JSONL storage, and optional AI
**advisory** (never required). It must work during a real incident from a
Python CLI and/or GUI **with no extra infrastructure** — no FastAPI, no Redis,
no Docker, no always-on background services, no "brain" server.

The code below is the infrastructure that had accreted around Coreline and pulled it
away from that model.

## What's here

| Item | What it was | Why archived |
|------|-------------|--------------|
| `coreline-brain-service/` | FastAPI "brain" server for PIR orchestration | Redundant — `coreline-brain.py` generates the PIR locally via the Claude API. Required FastAPI/uvicorn/Redis + a Dockerfile. |
| `slack-orchestrator/` | FastAPI + Redis Slack orchestration service | Background microservice + service orchestration; not part of the Lite model. |
| `jira-webhook-listener/` | FastAPI + Redis webhook listener | Always-on web API + Redis replay store; not required for CLI/GUI operation. |
| `grafana-webhook/` | Flask webhook receiver | Always-on web API; not required. |
| `brain-autonomous/` | `agent_orchestrator.py`, `recommendation_engine.py`, `test_autonomous_agent.py` | Autonomous-agent code. Coreline is human-in-the-loop; AI is advisory only. |

## What Coreline Lite kept

- `coreline.py` — the single operator CLI
- `coreline_gui/` — the optional desktop console
- `lib/`, `tools/` — storage, incident state, evidence, timeline, handoff,
  pre-closure, reports
- `coreline-brain.py` + `brain/assemble_pir_input.py` + `brain/generate_pir.py` —
  **local** PIR generation (optional AI advisory, no server)
- `services/coreline-slack-bot/` + `tools/evidence_bot_enhanced.py` — optional,
  lightweight slack-bolt integrations for evidence capture (Socket Mode, no web
  server)

## Reviving something

These directories still contain their own `requirements.txt`. If you ever need
one of these services, run it from here in its own environment — but do not make
Coreline Lite depend on it.
