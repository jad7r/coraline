# Coreline v3

**Incident response orchestration for the security team — driven from Claude Desktop.**

Coreline does the repetitive parts of incident response the same way every time: spin up the incident channel, assign roles, create the incident doc and Jira ticket, capture evidence, build a forensic timeline, and draft the post-incident review. Built for a 4-person trusted team. The Incident Commander wakes up at 3am and needs to move fast — Coreline is the muscle memory.

> **v3 (June 2026): direction change.** Coreline has pivoted from a Python service stack to a **Claude Desktop skill** backed by one small offline Python script. There is nothing to deploy, no daemon to keep alive, and **no Slack token issued to Python**. See [Why v3](#why-v3) for the history.

---

## How it works

- **Claude is the driver.** Kickoff, evidence capture, timeline, handoff, and PIR all run inside Claude Desktop using the connectors the team already has: **Slack**, **Jira/Confluence**, and **Google Drive**.
- **No service token for Python.** Claude reads Slack with the operator's own OAuth connector and hands a frozen events file to the timeline script. Python never holds a Slack token.
- **One manual step.** The Slack connector cannot create channels, so the IC creates the private channel by hand (~10 seconds) from the exact name Coreline provides. The skill does every other setup step.
- **Python is the forensic processor.** Timeline assembly is deterministic and reproducible from a frozen input — defensible as evidence in a way free-form LLM ordering is not. Claude generates the exact command; the **operator runs it locally**. It runs standalone, so the record survives a Claude outage.

---

## Architecture boundary — cloud orchestration vs. local execution

Coreline draws a hard line between what Claude does and what runs on your machine, and holds it deliberately: there is **no MCP server, no local daemon, no third-party Python dependency (`pip install`), and no editing of `claude_desktop_config.json`.** (A FastMCP/local-server wrapper was evaluated and **rejected** to preserve a zero-trust, fully operator-visible footprint.)

- **Cloud orchestration → Claude, via native connectors.** Channel setup, Jira ticket, canvas, evidence pull, Drive preservation, drafting. Claude acts through the operator's own OAuth connectors; nothing executes on the local host.
- **Local forensic compilation → the operator, via the CLI.** When the deterministic timeline is needed, **Claude generates the exact `build_timeline.py` command string** and the **human operator runs it locally**. Claude never executes code on your machine.

The trade-off is explicit and accepted: the IC opens a terminal once per incident. In exchange, the forensic engine stays plain Python 3 (stdlib only), fully inspectable, and runnable even if Claude is unavailable.

---

## Quick start

Claude Desktop loads skills from your **account**, not from a local folder — you
upload a ZIP. The folder inside the ZIP must be named `coreline` (lowercase) to match the
`name:` in `SKILL.md`, but the repo folder is `Coreline`, so stage a correctly-named copy
first (a plain `zip coreline` will be rejected).

```bash
# 1. Package the skill (run from the secops-tools repo root).
mkdir -p /tmp/coreline-pkg && cp -R coreline /tmp/coreline-pkg/coreline
( cd /tmp/coreline-pkg && zip -r coreline.zip coreline )

# 2. In Claude Desktop: Customize → Skills → + → Upload a skill,
#    choose /tmp/coreline-pkg/coreline.zip, then toggle it on.
#    It now appears under Customize → Skills.

# 3. Kick off an incident (natural language, in Claude Desktop):
#    "Declare a SEV1 ransomware incident on prod-webservers, I'm IC."
```

> **Claude Code (CLI) users:** Code discovers skills on the filesystem, so instead of
> uploading you can `cp -R coreline ~/.claude/skills/coreline` (folder must be lowercase `coreline`).
> Note: Claude **Desktop does not read** `~/.claude/skills/` — that path only works for
> the CLI.

The timeline script is standalone (Python 3, stdlib only — no `pip install`). Run it
straight from your repo clone — no skill install required:

```bash
# from the secops-tools repo root
python3 coreline/scripts/build_timeline.py \
  --events events.jsonl \
  --incident sec-ir-2026-06-26-ransomware-prod-webservers \
  --output timeline.md --csv timeline.csv --gap-minutes 30
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│   HUMAN OPERATORS (4-person team)                          │
│   IC · Technical Lead · Scribe · Comms Lead                │
└──────────────────────────────────────────────────────────┘
                          │ natural language
                          ▼
┌──────────────────────────────────────────────────────────┐
│   CLAUDE DESKTOP  +  Coreline skill (SKILL.md + templates)     │
│   orchestration · drafting · evidence pull · publishing    │
└──────────────────────────────────────────────────────────┘
        │ existing connectors (operator OAuth)        │ frozen events.jsonl
        ▼                                             ▼
┌─────────────────────────────────────┐   ┌──────────────────────────────┐
│  Slack  ·  Jira/Confluence  ·  Drive │   │  build_timeline.py (offline)  │
│  channel setup · ticket · canvas doc │   │  sort · dedupe · gap detect   │
│  evidence (📌) · preservation         │   │  → timeline.md / .csv         │
└─────────────────────────────────────┘   └──────────────────────────────┘
```

---

## What the skill does

| Operator says | Coreline does |
| --- | --- |
| "Declare a SEV1 ransomware incident on prod-webservers, I'm IC" | **Kickoff** — hands over the exact channel name to create, then posts the role message, builds the incident canvas, creates the Jira ticket, posts links, and schedules check-in reminders |
| React 📌 in-channel | **Evidence** — flagged messages and attachments are pulled on demand and preserved to the Drive incident folder |
| "Build the forensic timeline for `sec-ir-…`" | **Timeline** — Claude gathers events from Slack + Jira into `events.jsonl` and hands you the exact `build_timeline.py` command to run locally for a reproducible chronology with gap detection. Claude does **not** execute code on your machine — you run the command |
| "Handoff to Bob" | **Handoff** — current state, last 24h, evidence gaps, open actions; posted and canvas updated |
| "Write the PIR" | **PIR** — drafts the post-incident review from timeline + canvas + Jira, with PII/secret redaction |

---

## Naming convention

- **Incident ID / channel:** `sec-ir-YYYY-MM-DD-<type>-<short-desc>`
  - `<type>`: `ransomware`, `phishing`, `bec`, `malware`, `data-breach`, `account-takeover`
  - Example: `sec-ir-2026-06-26-ransomware-prod-webservers`
- **Severity:** `SEV1` (critical) · `SEV2` (high) · `SEV3` (moderate)
- **States:** `DECLARED → INVESTIGATING → CONTAINED → ERADICATED → RECOVERED → CLOSED`

---

## Repository layout

```
coreline/
├── SKILL.md                  # orchestration: kickoff, evidence, timeline, handoff, PIR
├── templates/
│   ├── roles.md              # kickoff / role-assignment Slack message
│   ├── incident-doc.md       # incident canvas (living doc)
│   └── jira-incident.md      # Jira ticket field mapping
├── scripts/
│   └── build_timeline.py     # deterministic forensic timeline builder (stdlib only)
└── INSTALL.md                # install + usage
```

---

## Channel creation

The connector cannot create Slack channels, so the IC creates the private channel manually from the name Coreline supplies. If full automation of this step is wanted later, the **smallest possible IT ask** is a Slack app scoped to **`channels:manage` only** — far narrower than the old broad bot token. Until then, the manual step costs ~10 seconds and needs no token.

---

## Resilience: what happens if Claude is down

Coreline is built so the forensic record never depends on Claude being available:

- **Evidence collection continues in Slack.** The team keeps reacting 📌 in-channel — no tooling required.
- **The timeline is offline-capable.** `build_timeline.py` is plain Python 3 (stdlib only, no network, no tokens). Given an events file exported from the Slack channel and Jira, it produces the full forensic timeline with gap detection — Claude not required.
- **Deterministic and reproducible.** Re-running the script on the same input yields the exact same timeline, which is what makes it defensible as evidence.
- **Run it from the repo clone, not the skill install.** Whether Claude Desktop executes a skill's bundled Python locally or server-side isn't publicly documented, and code execution may depend on plan tier. The guaranteed-offline path is to run `python3 coreline/scripts/build_timeline.py` directly from the secops-tools clone — no skill install, no Claude, no network required.

In short: Claude makes the common path fast; Python guarantees the record.

---

## Why v3

| | v1 | v2 | v3 (current) |
| --- | --- | --- | --- |
| Form | npm package / web app | Python script suite + microservices | Claude Desktop skill + 1 script |
| Driver | Web UI | `incident_kickoff.py`, `evidence_bot.py`, services | Claude, via natural language |
| Slack | bot token | broad bot token + always-on evidence daemon | operator OAuth connector; 📌 pulled on demand |
| Channel creation | automated (broad token) | automated (broad token) | manual (10s); skill does the rest |
| Python's role | n/a | everything | forensic timeline only — no token, deterministic |
| To deploy / maintain | hosting | secrets, secure enclave, GCP, webhooks, services | nothing to run |

**The problem v3 solves:** v2 grew into microservices, a secure enclave, GCP WORM storage, Grafana sync, an IOC tracker, and a dashboard server — and it required a broad Slack token IT was reluctant to issue. That is the opposite of "IC wakes up at 3am and gets it done." v3 leans on tools the team already uses and removes the operational tax.

**Dropped from the core path (by design):** GCP WORM bucket, secure enclave, Grafana IRM sync, cross-incident IOC tracker, dashboard server, interactive Slack bot service.

> **Retention tradeoff.** Drive preservation is **not** write-once. If an incident requires WORM-grade immutable retention (1-year locked), that still needs the GCP path and should be flagged when it matters.

---

## Principles

1. **Simplicity over complexity** — a skill, not a service stack.
2. **Human authority, AI assistance** — Claude drafts and orchestrates; humans decide.
3. **Evidence first** — capture as you go, preserve before closing.
4. **Operational velocity** — reduce toil, don't add governance.

---

## Compliance targets

- ISO 27001:2022 A.16 (Information security incident management)
- NIST SP 800-61r2 (Computer Security Incident Handling Guide)
- FedRAMP IR-4 (Incident Handling), IR-5 (Incident Monitoring), IR-8 (Incident Response Plan)
- PCI DSS v4.0 (Incident response procedures)

---

## Documentation

| Document | Purpose |
| --- | --- |
| [Confluence: Project Coreline](https://example.atlassian.net/wiki/spaces/VULCAN/pages/4879646745/Project+Coreline+Automated+Response+Evidence+System) | Canonical project page |
| `coreline/INSTALL.md` | Install + usage |
| `coreline/SKILL.md` | Skill orchestration reference |

---

## Contact

Security Operations Team. Internal use only — proprietary.
