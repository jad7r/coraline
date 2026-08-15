---
name: coreline
description: >
  Coreline — incident response orchestration for the security team. Use when
  declaring or kicking off a security incident, spinning up an incident Slack channel
  consistently, assigning IC/Tech Lead/Scribe/Comms roles, creating the incident doc
  and Jira ticket, flagging evidence, building a forensic timeline, or generating a
  handoff or post-incident review (PIR). Trigger on "declare an incident", "kick off
  an incident", "spin up an incident channel", "IC", "incident commander", "build the
  timeline", "evidence", "handoff", or "PIR".
---

# Coreline — Automated Response & Evidence System (v3)

Incident orchestration that runs from Claude Desktop using the connectors you already
have. **The Incident Commander (IC) wakes up at 3am and needs to move fast.** This
skill does the repetitive setup the same way every time, keeps a forensic record, and
hands off cleanly.

## Design (v3)

- **Claude is the driver.** Orchestration runs here in Claude Desktop using the
  **Slack**, **Jira/Confluence**, and **Google Drive** connectors. No service to deploy,
  no daemon to keep alive.
- **No Slack token for Python.** Python never touches Slack. Claude reads Slack with
  *your* OAuth connector and hands data to a small offline script.
- **One manual step.** The connector cannot create Slack channels, so the IC creates
  the channel by hand (≈10 seconds). The skill does everything else.
- **Python is the forensic processor.** Timeline assembly is deterministic and
  reproducible — defensible as evidence in a way that free-form LLM ordering is not.
  Claude generates the command; the **operator runs it locally**. Claude never executes
  code on the host.

If a connector isn't available in this session, say so and continue with whatever is —
never silently skip a step.

---

## Command Map

| You say | Coreline does |
|---|---|
| "declare / kick off an incident" | [Kickoff](#flow-kickoff) — channel setup, roles, canvas doc, Jira ticket |
| "flag that as evidence" / 📌 | [Evidence](#flow-evidence) — pull 📌-flagged messages, preserve to Drive |
| "build the timeline" | [Timeline](#flow-timeline) — assemble forensic timeline via Python |
| "handoff to <name>" | [Handoff](#flow-handoff) — current state, last 24h, open actions |
| "write the PIR" | [PIR](#flow-pir) — post-incident review draft |

---

## Naming Convention (never deviate)

- **Incident ID / channel:** `sec-ir-YYYY-MM-DD-<type>-<short-desc>`
  - `<type>`: `ransomware`, `phishing`, `bec`, `malware`, `data-breach`, `account-takeover`
  - `<short-desc>`: 1–3 words, lowercase, hyphenated (e.g. `prod-webservers`)
  - Use today's date (run `date +%F` if unsure).
  - Example: `sec-ir-2026-06-26-ransomware-prod-webservers`
- **Severity:** `SEV1` (critical) · `SEV2` (high) · `SEV3` (moderate)
- **States:** `DECLARED → INVESTIGATING → CONTAINED → ERADICATED → RECOVERED → CLOSED`

---

## Flow: Kickoff {#flow-kickoff}

Goal: from "we have an incident" to a fully set-up channel in under two minutes.

**1. Gather four things** (ask only for what's missing — don't interrogate at 3am):
severity, type, short description, and who is IC. Default IC to the current user.

**2. Compute the incident ID** from the naming convention and show it. Then give the
IC the exact channel name to create:

> Create a **private** Slack channel named exactly:
> `sec-ir-2026-06-26-ransomware-prod-webservers`
> Tell me when it exists (or paste the channel link).

Wait for confirmation. This is the only manual step.

**3. Resolve the channel.** Use `slack_search_channels` to find it and get its ID.

**4. Post the kickoff message.** Read `templates/roles.md`, fill in the placeholders,
and post to the channel with `slack_send_message`. This assigns roles and states the
incident header.

**5. Create the incident canvas** (the living incident doc). Read
`templates/incident-doc.md`, fill placeholders, and create it with
`slack_create_canvas` attached to the channel. This is the source of truth during the
incident — update it with `slack_update_canvas` as things change.

**6. Create the Jira ticket.** Read `templates/jira-incident.md` for the field mapping
and create it with `createJiraIssue` in the security project (confirm the project key
with the user the first time; default to the team's security project). Capture the
issue key + URL.

**7. (Optional) Google Doc** for long-form notes / customer comms — create via the
Drive connector's `create_file` only if the user wants one beyond the canvas.

**8. Post the "kickoff complete" summary** to the channel: incident ID, severity,
state `DECLARED`, IC, links to the canvas and Jira ticket.

**9. Offer reminders.** Use `slack_schedule_message` to schedule SEV-appropriate
check-in nudges (SEV1: every 30 min; SEV2: hourly) into the channel.

Keep step output tight. The IC is working the incident, not reading you.

---

## Flow: Evidence {#flow-evidence}

There is no always-on bot in v3. Evidence is flagged with the 📌 reaction and pulled
**on demand** (at any point, and always before timeline/PIR).

1. Read the channel (`slack_read_channel`) and threads (`slack_read_thread`).
2. For candidate messages, check reactions with `slack_get_reactions`; keep those with
   📌 (`pushpin`).
3. For each flagged item, capture: timestamp, author, text, permalink, and any file
   (`slack_read_file`).
4. **Preserve it.** Save each evidence item (and attachments) into the incident's
   Google Drive folder via the Drive connector so there's a copy independent of Slack
   retention. Record what you saved.
5. Mark each preserved item `"evidence": true` in the events file (see Timeline).

> **Retention note (v3 tradeoff):** the old GCP WORM bucket (1-year immutable) is not
> wired into the connector path. Drive preservation is not write-once. If true WORM
> immutability is required for a given incident, flag it to the user — that still needs
> the GCP path.

---

## Flow: Timeline {#flow-timeline}

A forensic timeline must be reproducible. Claude **gathers** the events and **hands the
operator the command**; the bundled Python script, **run locally by the human operator**,
**orders, dedupes, and flags gaps** deterministically. Claude never executes code on the
operator's machine.

**1. Gather events** and provide the JSONL contents for the operator to save as
`events.jsonl` in their working directory, one JSON object per line. Pull from every
available source:

- Slack: every message + state-change post + 📌 evidence (`slack_read_channel`,
  `slack_read_thread`, `slack_get_reactions`)
- Jira: ticket creation, transitions, comments (`getJiraIssue`, comments)
- Drive: doc/evidence file creation times if relevant

Each line uses this schema (the script's contract — keep it exact):

```json
{"ts": "2026-06-26T14:03:00Z", "source": "slack", "actor": "alice@example.com", "type": "message", "text": "isolating host", "ref": "https://slack.com/...", "evidence": false}
```

- `ts`: ISO-8601 (`...Z`) **or** a Slack epoch string like `"1750000000.000200"`.
- `source`: `slack` | `jira` | `drive` | `manual`
- `type`: `message` | `state_change` | `evidence` | `jira_comment` | `action`
- `evidence`: `true` for 📌-flagged / preserved items.

**2. Instruct the human operator to open their local terminal and run the timeline
builder script exactly as follows** — Claude does **not** execute this itself. (The
snippet locates the script first; it ships in this skill's `scripts/`.)

```bash
# Look where a CLI install (~/.claude) or a Desktop-synced skill (~/Library) would put
# it; fall back to a secops-tools repo clone, which always has it under Coreline/scripts/.
SCRIPT=$(find ~/.claude ~/Library -path '*/coreline/scripts/build_timeline.py' -type f 2>/dev/null | head -1)
SCRIPT=${SCRIPT:-$(find ~ -path '*/Coreline/scripts/build_timeline.py' -type f 2>/dev/null | head -1)}
python3 "$SCRIPT" --events events.jsonl \
  --incident sec-ir-2026-06-26-ransomware-prod-webservers \
  --output timeline.md --csv timeline.csv --gap-minutes 30
```

The script outputs a chronological Markdown timeline (evidence marked 📌, gaps >30 min
flagged ⚠️) plus a CSV, and prints summary stats (start, end, duration, counts).

**3. Publish** the timeline: update the canvas, attach to the Jira ticket, and/or save
to the Drive incident folder.

Do **not** hand-sort the timeline yourself, and do **not** claim to have run it — the
**operator** runs the script locally so the result is reproducible and defensible.

---

## Flow: Handoff {#flow-handoff}

When the IC changes (shift change, escalation):

1. Build/refresh the timeline (above).
2. Summarize from the canvas + Jira + last 24h of channel activity:
   current state, what's confirmed, what's open, evidence gaps, immediate next actions.
3. Post the handoff to the channel and @-mention incoming + outgoing IC.
4. Update the canvas header with the new IC and timestamp.

---

## Flow: PIR {#flow-pir}

Post-incident review, after `RECOVERED`/`CLOSED`:

1. Ensure the timeline is final and evidence is preserved.
2. Draft the PIR from timeline + canvas + Jira: summary, impact, detection,
   chronology, root cause, what worked / what didn't, action items (owners + dates),
   compliance notes (ISO 27001 A.16, NIST 800-61r2, FedRAMP IR-4/5/8).
3. **Redact** emails, secrets, tokens, and customer PII in anything shared beyond the
   team.
4. For a formatted deliverable, use the `pantheon-docs` or `docx` skill to produce the
   Word document. The human reviews and publishes — Claude drafts, humans decide.

---

## Files in this skill

- `templates/roles.md` — kickoff / role-assignment Slack message
- `templates/incident-doc.md` — incident canvas (living doc) template
- `templates/jira-incident.md` — Jira incident ticket field mapping
- `scripts/build_timeline.py` — deterministic forensic timeline builder (stdlib only)

## Principles (carried over from Coreline)

1. Simplicity over complexity.
2. Human authority, AI assistance — Claude drafts and orchestrates; humans decide.
3. Evidence first — capture as you go; preserve before closing.
4. Operational velocity — reduce toil, don't add governance.
