# Kickoff / Role-Assignment Message

Posted to the incident channel immediately after creation. Fill the `{{...}}`
placeholders, then send with `slack_send_message`. Keep it scannable — this is the
first thing the team sees.

---

🚨 *Security Incident Declared* — `{{INCIDENT_ID}}`

*Severity:* {{SEVERITY}}  ·  *State:* `DECLARED`  ·  *Declared:* {{TIMESTAMP}}
*Summary:* {{ONE_LINE_DESCRIPTION}}

*Roles* — claim yours by replying in-thread:
• 🧭 *Incident Commander (IC):* {{IC}}  ← drives the response, owns decisions
• 🔧 *Technical Lead:* _unassigned_  ← leads investigation & remediation
• ✍️ *Scribe:* _unassigned_  ← keeps the canvas + timeline current
• 📣 *Comms Lead:* _unassigned_  ← stakeholder / customer / leadership updates

*How we work this channel:*
• 📌 React with the pushpin emoji on any message that is *evidence* — it gets pulled into the forensic record.
• Post state changes as: `STATE → INVESTIGATING (reason)`
• Incident doc (canvas) and Jira ticket are linked below.

_Links posted in the next message once setup completes._
