# Project Coreline — Project Summary (v3)

**Automated Response & Evidence System** · Coreline Security Operations
*Last updated: 2026-06-26 · Internal use only — proprietary*

---

## 📌 Overview

Coreline is our internal, lightweight incident-response orchestration pipeline — the
in-house answer to incident.com, sized for a **4-person team**. It does the repetitive
parts of IR the same way every time: spin up the incident channel, assign roles, create
the incident doc and Jira ticket, capture evidence, build a defensible forensic
timeline, and draft the post-incident review (PIR).

**v3 is a direction change.** Coreline has pivoted from a Python service stack (microservices,
daemons, a broad Slack bot token, a secure enclave) to a **Claude Desktop skill backed by
one small offline Python script**. The orchestrator is now Claude, driven in natural
language through the connectors the team already has — Slack, Jira/Confluence, and Google
Drive (Enterprise). There is nothing to deploy and no standing service token to guard.

The system keeps the **nature** of the original scope — structured response, immutable
evidence, a defensible audit trail, ISO/FedRAMP alignment — while shedding the operational
tax that made v2 the opposite of "the IC wakes up at 3am and just gets it done."

### The one fundamental shift

The original design was **event-driven**: a daemon intercepted a Jira trigger, fired a
webhook, spawned a channel, subscribed to emoji events, called the API, and committed to a
vault — autonomously, while holding tokens. v3 replaces the daemon with **a human saying
"declare an incident"** and Claude executing the steps through the operator's own OAuth
connectors. We trade *autonomous reactivity* for *human-in-the-loop with zero standing
infrastructure*. For a trusted 4-person team that is a feature, not a loss.

---

## 🗺️ How it works

- **Claude is the driver.** Kickoff, evidence capture, timeline, handoff, and PIR all run
  inside Claude Desktop using existing connectors. No daemon, no hosting.
- **No service token for Python.** Claude reads Slack with the operator's OAuth connector
  and hands a frozen events file to the timeline script. Python never holds a token.
- **One manual step.** The Slack connector can't create channels, so the IC creates the
  private channel by hand (~10s) from the exact name Coreline supplies. The skill does every
  other setup step.
- **Python is the forensic processor.** Timeline assembly is deterministic and reproducible
  from a frozen input — defensible as evidence in a way free-form LLM ordering is not.
  Claude generates the exact command; the **operator runs it locally**. It runs standalone,
  so the record survives a Claude outage.
- **Immutable archival is platform-enforced.** Claude deposits the PIR and preserved
  evidence into a Google Drive location an admin has placed under a Vault retention hold.
  Google enforces WORM; Claude just deposits. (See [Evidence integrity & WORM](#-evidence-integrity--worm).)

```
HUMAN OPERATORS (IC · Tech Lead · Scribe · Comms)
        │ natural language
        ▼
CLAUDE DESKTOP  +  Coreline skill (SKILL.md + templates)
        │ operator OAuth connectors            │ frozen events.jsonl
        ▼                                       ▼
Slack · Jira/Confluence · Google Drive    build_timeline.py (offline)
channel setup · ticket · canvas ·         sort · dedupe · gap detect
evidence (📌) · WORM deposit              → timeline.md / .csv
```

---

## 🧱 Architecture boundary (decision: pure skill + standard CLI)

Coreline draws one hard line and holds it deliberately. **Claude orchestrates through its
native cloud connectors; local forensic compilation is run by the human operator from a
standard terminal.** There is **no MCP server, no local daemon, no third-party Python
dependency (`pip install`), and no editing of `claude_desktop_config.json`.**

| Layer | Who | How |
|---|---|---|
| **Cloud orchestration** | Claude | Channel setup, Jira ticket, canvas, evidence pull, Drive/WORM deposit, drafting — all via the operator's own OAuth connectors. Nothing runs on the local host. |
| **Local forensic compilation** | Operator | Claude **generates the exact `build_timeline.py` command string**; the human runs it locally. Claude never executes code on the machine. |

**Decision record — a local MCP server was evaluated and rejected.** A FastMCP wrapper
(`server.py`) exposing a local timeline tool to Claude Desktop was proposed and turned
down. Reasons: it would reintroduce a daemon, a `pip install mcp` dependency, and a
hand-edited desktop config — reversing the v3 "nothing to deploy / stdlib only" promise —
and it would weaken the outage-resilience guarantee. The accepted trade-off is that the
IC opens a terminal once per incident, in exchange for a **100% operator-visible,
zero-trust footprint** where the forensic engine stays plain, inspectable Python 3 that
runs even if Claude is unavailable. The existing `build_timeline.py` is kept exactly as
is (UTC-correct, deterministic, dedupe + gap detection + CSV).

---

## 🔄 Original scope, reconciled to v3

The original project was organized into four tactical tracks. Here is where each lands
under Claude-as-orchestrator.

Legend: ✅ Claude does it natively · ⚠️ Claude + a one-time human/admin setup ·
🔴 Not Claude — needs a thin piece of infra outside the orchestrator

### 🟢 Track 1 — Coreline-Comm (Communications & Orchestration) · *Owner: Kos Pavlenko*

| Original task | Disposition | Notes |
|---|---|---|
| 1.1 Hardened `Coreline-Bot` Slack app (`channels:manage` + `groups:write`) | ⚠️ | Connector covers messaging, canvas, reactions, scheduling, reads — **no stored bot token**. Channel *creation* is the only gap: manual 10s step, or the smallest possible app scoped to `channels:manage` only. |
| 1.2 Webhook listener: Jira "New Incident" → auto-spawn channel | ✅ *(reframed)* | The daemon goes away. Claude is triggered by the IC, creates the Jira ticket, and hands over the exact channel name. **Deterministic naming survives** as a skill template; autonomous Jira→Slack triggering does not. |
| 1.3 📌 emoji event subscription parsed as evidence | ✅ *(on-demand)* | The `:pushpin:` = evidence convention is fully preserved. Claude pulls flagged messages via the connector on request; capture continues in Slack even if Claude is offline. |

**Verdict:** the coordination highway is fully Claude. Only true gap is channel creation.

### 🔵 Track 2 — Coreline-Brain (Synthesis & Prompt Engineering) · *Owner: Jake Choi*

| Original task | Disposition | Notes |
|---|---|---|
| 2.1 Locked Jira Issue Type + embedded Markdown runbook | ⚠️ | Issue-type lockdown is a one-time Jira-admin config; Claude *uses* it. Runbook lives as a skill template. |
| 2.2 System prompt → synthesize Jira + Slack + 📌 into the Coreline PIR layout | ✅ | The heart of the system, and Claude's native strength. Realized as `SKILL.md` + templates. |
| 2.3 Objective tone, noise filtering, auditor-friendly output | ✅ | Prompt constraints in the skill — strip chatter, stay factual/legal. |

**Verdict:** this track doesn't just survive — it gets *better*, because synthesis is
Claude's core competency rather than a brittle integration we maintain.

### 🟡 Track 3 — Coreline-Vault (Immutable Archive) · *Owner: TBD*

| Original task | Disposition | Notes |
|---|---|---|
| 3.1 Isolated Shared Drive, service-account-only write | ⚠️ | Claude writes the PIR/evidence to the incident folder via the operator's Drive connector. No service account — folder permissions are an admin setup. |
| 3.2 **WORM, 3-year retention hold, Viewer-only** | ✅ *(platform-enforced)* | Admin puts a Shared Drive/folder under a Google Vault retention hold (Enterprise Workspace). Claude **deposits** into it; **Google enforces immutability**. Claude never enforces WORM — the control lives in the platform an auditor already trusts. |
| 3.3 Markdown → PDF/Doc, commit to vault | ✅ | Claude creates the Doc in the locked folder via connector — no custom backend script. |

**Verdict:** archival *and* immutability are now in scope. See the dedicated section below.

### 🔴 Track 4 — Coreline-Assurance (Compliance & Validation) · *Owner: Lead*

| Original task | Disposition | Notes |
|---|---|---|
| 4.1 Secret management & IAM audit (no hardcoded tokens) | ✅ *(dissolves)* | **Biggest win.** Operator OAuth connectors replace the Slack bot token, the Anthropic API key, and the Google service-account key. The Python script holds no token. There is almost nothing left to store, rotate, or leak. |
| 4.2 Structured JSON to SIEM per step (non-repudiation) | 🔴 | The one item still not Claude's to own. No single pipeline emits consolidated logs. Non-repudiation lives in each tool's **native** audit trail (Slack / Jira / Drive / Anthropic enterprise), attributed to the operator, plus the deterministic timeline. Centralized SIEM consolidation is a separate, optional log-export integration. |
| 4.3 Tabletop fire drill (mock P1) | ✅ | Run an end-to-end mock incident with Claude orchestrating; pure validation. |

**Verdict:** secrets management largely evaporates; SIEM consolidation is the lone open item.

---

## 🔒 Evidence integrity & WORM

We retain WORM-grade immutable retention — the responsibility is simply split correctly:

1. **An admin configures the locked location once** — a Google Shared Drive (or folder)
   under a Vault retention hold / retention rule (Enterprise Workspace). The hold blocks
   purge and deletion even for editors, for the retention period (≥3 years, FedRAMP
   alignment).
2. **The skill is pinned to that Drive/folder ID** so every incident lands in the locked
   location and a typo can't silently write somewhere mutable.
3. **Claude deposits** the PIR and preserved evidence there via the Google Drive
   (Enterprise) connector.

**Operating rules that keep it audit-defensible:**

- **Immutability is the retention rule, not the permissions.** The operator needs write
  access to *deposit*; the Vault hold is what prevents *tampering*. "Only the automation
  can write" (old 3.1 goal) and "the record can't be altered" (the actual integrity goal)
  are different — the hold delivers the second regardless of who holds write.
- **Write new, never overwrite.** Claude lands each artifact as a new, sequentially-named
  file (`PIR-001`, `EV-002`, …). Amendments are distinct, sequentially numbered appendix
  files — never in-place edits. This matches the original evidence-integrity rule and
  keeps integrity in clean append-only files rather than relying on version history.
- **Verify the hold in the drill.** The tabletop (4.3) confirms the destination is under an
  active retention hold before we trust it in a real P1.

---

## ✅ Compliance targets

| Standard | How v3 meets it |
|---|---|
| **ISO 27001 A.12.6.1 / A.16** | Structured, repeatable incident procedures (skill); evidence retention (WORM Drive); access logging (native tool audit trails). |
| **FedRAMP IR-4 / IR-5 / IR-8** | Documented response plan + playbooks; deterministic timeline for incident monitoring; WORM retention on Drive for preservation. |
| **FedRAMP data-privacy boundary** | ⚠️ *Procurement/config, not build.* All telemetry now flows through Claude Desktop, so the org must confirm the **enterprise/Team tier with zero-data-retention** explicitly active (no training on our data). More important under v3, not less — owned by whoever holds the Anthropic contract. |
| **PCI DSS v4.0** | Documented IR procedures + evidence trail. |

---

## ⚠️ Open items

- **SIEM non-repudiation (Track 4.2).** Decide whether audit must be *consolidated* in our
  SIEM (a separate log-export integration, independent of Coreline) or whether per-tool native
  audit logs are sufficient for a 4-person trusted team. This is the only original goal not
  covered by the orchestrator.
- **Anthropic enterprise tier + ZDR confirmation.** Verify the data-privacy boundary before
  Coreline handles a real incident.
- **Track 3 / Track 4 owners** still to be assigned.

---

## 🧭 Conventions

- **Incident ID / channel:** `sec-ir-YYYY-MM-DD-<type>-<short-desc>`
- **`<type>`:** ransomware · phishing · bec · malware · data-breach · account-takeover
- **Severity:** SEV1 (critical) · SEV2 (high) · SEV3 (moderate)
- **States:** DECLARED → INVESTIGATING → CONTAINED → ERADICATED → RECOVERED → CLOSED

---

## 📚 Where things live

| Document | Purpose |
|---|---|
| `Coreline/README.md` | Project front door + quick start |
| `Coreline/INSTALL.md` | Install (Desktop ZIP upload + CLI) and usage |
| `Coreline/SKILL.md` | Skill orchestration reference (kickoff, evidence, timeline, handoff, PIR) |
| `Coreline/scripts/build_timeline.py` | Deterministic offline forensic timeline builder |
| `Coreline/templates/` | Roles message, incident canvas, Jira field mapping |

---

## 🪶 Net picture

With the admin-configured WORM Drive, **Claude-as-orchestrator covers the original intent
almost completely** — synthesis, coordination, evidence capture, deterministic timeline,
*and* immutable archival — while shedding all the secrets and standing infrastructure that
made v2 unsustainable. The lone genuine asterisk is whether leadership wants audit
*consolidated in a SIEM* or is content with per-tool native logs. Everything else the
original four tracks set out to do, we keep.
