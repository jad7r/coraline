"""
Minimal local shims for the ``lib`` layer this service depends on.

The real implementations (``lib.grafana_irm.GrafanaToCorelineSync`` and
``lib.storage.JSONLStorage``) are being reconstructed by a parallel effort and are
NOT present in this worktree. To keep this service independently mergeable and
testable, we vendor minimal stand-ins here that satisfy the interface main.py uses.

# TODO(ADR-0003 integration): swap to lib.grafana_irm / lib.storage
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


class GrafanaToCorelineSync:
    """Syncs Grafana IRM webhook events into Coreline.

    Shim: records the event and echoes a factual acknowledgement. The real
    implementation will create/update Coreline incidents from the payload.
    """

    def handle_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process a Grafana IRM webhook payload.

        Args:
            payload: Parsed webhook JSON.

        Returns:
            A JSON-serializable result describing what was done.
        """
        event_type = payload.get("event_type")
        incident = payload.get("incident") or {}
        return {
            "status": "accepted",
            "event_type": event_type,
            "grafana_incident_id": incident.get("id"),
            "synced_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }


class JSONLStorage:
    """Append-only JSON Lines storage.

    Shim: writes one JSON object per line to a local file, creating parent
    directories as needed.
    """

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def append(self, entry: Dict[str, Any]) -> None:
        """Append a single entry as a JSON line."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
