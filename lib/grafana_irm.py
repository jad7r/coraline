"""
Grafana IRM webhook -> Coreline incident-action mapping.

``GrafanaToCorelineSync`` is a **pure, deterministic translator**: given a Grafana IRM webhook
payload it returns a normalized Coreline incident *action* dict. It performs no network I/O and
writes no state — per ADR-0002 the deterministic core owns state, so this layer only
proposes an action for the core to apply. That makes it trivial to unit-test offline.

Supported events (from ``archive/experimental/grafana-webhook/main.py`` docstring):

    incident.created        -> declare a new Coreline incident
    incident.acknowledged   -> move incident to ACKNOWLEDGED / assign
    incident.resolved       -> resolve the incident
    incident.note.created   -> append a note to the incident timeline

Payload shape (as the webhook receiver hands it over)::

    {
      "event_type": "incident.created",
      "incident": {"id": "...", "title": "...", "severity": "critical", ...},
      "note": {...}   # only for note.created
    }

The mapping is total: an unknown/missing ``event_type`` yields an ``action == "ignore"``
result with a reason, rather than raising — the always-on receiver must never 500 on an
event type it simply doesn't handle.
"""
from __future__ import annotations

from typing import Any

# Grafana severity strings -> Coreline canonical severities. Grafana IRM uses these labels;
# anything unrecognized passes through as "unknown" so we never silently downgrade.
_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "sev1": "critical",
    "major": "high",
    "sev2": "high",
    "high": "high",
    "warning": "medium",
    "minor": "medium",
    "sev3": "medium",
    "medium": "medium",
    "info": "low",
    "low": "low",
    "sev4": "low",
}

# Grafana event_type -> Coreline action verb.
_EVENT_ACTION: dict[str, str] = {
    "incident.created": "declare_incident",
    "incident.acknowledged": "acknowledge_incident",
    "incident.resolved": "resolve_incident",
    "incident.note.created": "append_note",
}


class GrafanaToCorelineSync:
    """Deterministic Grafana IRM -> Coreline incident-action mapper. Stateless."""

    def __init__(self, source: str = "grafana-irm"):
        # ``source`` is stamped onto every action so the Coreline core can attribute provenance.
        self._source = source

    def normalize_severity(self, severity: "str | None") -> str:
        if not severity:
            return "unknown"
        return _SEVERITY_MAP.get(str(severity).strip().lower(), "unknown")

    def handle_webhook(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Map a Grafana IRM webhook payload to an Coreline incident action.

        Always returns a dict; never raises on unknown event types (returns an
        ``action == "ignore"`` envelope instead). Raises ``TypeError`` only if ``payload``
        is not a dict, which is a programming error at the call site.
        """
        if not isinstance(payload, dict):
            raise TypeError(f"payload must be a dict, got {type(payload).__name__}")

        event_type = payload.get("event_type")
        incident = payload.get("incident") or {}
        if not isinstance(incident, dict):
            incident = {}

        action = _EVENT_ACTION.get(event_type)
        if action is None:
            return {
                "action": "ignore",
                "source": self._source,
                "event_type": event_type,
                "reason": "unsupported_event_type",
            }

        grafana_id = incident.get("id")
        result: dict[str, Any] = {
            "action": action,
            "source": self._source,
            "event_type": event_type,
            "grafana_incident_id": grafana_id,
            # External correlation id Coreline uses to dedupe repeat webhooks for one incident.
            "external_ref": f"grafana:{grafana_id}" if grafana_id else None,
        }

        if action == "declare_incident":
            result["fields"] = {
                "title": incident.get("title"),
                "severity": self.normalize_severity(incident.get("severity")),
                "description": incident.get("description"),
                "status": "open",
            }
        elif action == "acknowledge_incident":
            result["fields"] = {
                "status": "acknowledged",
                "acknowledged_by": incident.get("acknowledged_by")
                or incident.get("assignee"),
            }
        elif action == "resolve_incident":
            result["fields"] = {
                "status": "resolved",
                "resolution": incident.get("resolution")
                or incident.get("resolution_note"),
            }
        elif action == "append_note":
            note = payload.get("note") or {}
            if not isinstance(note, dict):
                note = {}
            result["note"] = {
                "body": note.get("body") or note.get("text"),
                "author": note.get("author") or note.get("created_by"),
            }

        return result
