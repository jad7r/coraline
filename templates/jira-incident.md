# Jira Incident Ticket — Field Mapping

Create with `createJiraIssue`. Confirm the **project key** with the user the first time
(default to the team's security/incident project) and store it for reuse. If a field
below doesn't exist in the project, fall back to putting it in the description rather
than failing the create.

## Fields

| Jira field | Value |
|---|---|
| Project | `{{SECURITY_PROJECT_KEY}}` (confirm once, then reuse) |
| Issue type | `Incident` (or `Bug`/`Task` if Incident type is unavailable) |
| Summary | `[{{SEVERITY}}] {{INCIDENT_ID}} — {{ONE_LINE_DESCRIPTION}}` |
| Priority | SEV1→Highest · SEV2→High · SEV3→Medium |
| Labels | `security-incident`, `coreline`, `{{TYPE}}` |
| Assignee | {{IC}} |

## Description (ADF/markdown body)

```
*Incident:* {{INCIDENT_ID}}
*Severity:* {{SEVERITY}}
*State:* DECLARED
*Declared:* {{TIMESTAMP}}
*IC:* {{IC}}

*Summary*
{{ONE_LINE_DESCRIPTION}}

*Slack channel:* #{{INCIDENT_ID}}
*Incident canvas:* {{CANVAS_URL}}

*Type / playbook:* {{TYPE}}

_Tracked by Coreline. State transitions and timeline updated as the incident progresses._
```

## After creation
- Capture the issue **key** and **URL** — they go into the kickoff summary message and
  the canvas header.
- On each state change, add a comment via `addCommentToJiraIssue` and (if a workflow
  status maps) transition with `transitionJiraIssue`.
