# Incident Canvas (Living Doc)

The single source of truth during the incident. Create with `slack_create_canvas`
attached to the channel; keep current with `slack_update_canvas`. Fill `{{...}}`.

---

# {{INCIDENT_ID}}

| | |
|---|---|
| **Severity** | {{SEVERITY}} |
| **State** | `DECLARED` |
| **Declared** | {{TIMESTAMP}} |
| **Incident Commander** | {{IC}} |
| **Jira** | {{JIRA_URL}} |
| **Channel** | #{{INCIDENT_ID}} |

## Roles
- 🧭 IC: {{IC}}
- 🔧 Tech Lead: _unassigned_
- ✍️ Scribe: _unassigned_
- 📣 Comms: _unassigned_

## Summary
{{ONE_LINE_DESCRIPTION}}

## Current Status
_Updated by Scribe. What do we know right now?_

## State Log
| Time | State | By | Reason |
|---|---|---|---|
| {{TIMESTAMP}} | DECLARED | {{IC}} | Incident declared |

## Working Theory / Root Cause
_Hypotheses, confirmed/ruled-out. Mark assumptions as assumptions._

## Actions Taken
| Time | Action | By |
|---|---|---|
| | | |

## Evidence
_Items flagged with 📌 in-channel, preserved to Drive. Builder pulls these into the timeline._
- [ ]

## Affected Systems / Scope
-

## Comms Log
_Stakeholder, customer, leadership updates and timestamps._

## Open Questions / Next Actions
- [ ]

## Playbook
Type: {{TYPE}} — follow the matching runbook (ransomware / phishing / bec / malware /
data-breach / account-takeover). Track step completion here.
