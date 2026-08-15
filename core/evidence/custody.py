"""
Chain-of-custody: an append-only, hash-linked log of actions taken on evidence.

Each event records who did what and when, and links to the previous event via
``previous_hash == prior.entry_hash()``. Altering or reordering any interior event
breaks the linkage, so the chain is tamper-evident. Deterministic; stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.evidence._util import canonical_json, to_iso
from core.evidence.hashing import sha256_bytes


@dataclass(frozen=True)
class CustodyEvent:
    """One tamper-evident custody record.

    Fields:
      collector      -- identity performing the action (e.g. "alice@example.com")
      action         -- what was done (e.g. "collected", "preserved", "sealed")
      timestamp      -- ISO-8601 UTC instant of the action
      target         -- what it acted on (an item sha256, or "manifest"); optional
      details        -- optional JSON-safe extra context
      previous_hash  -- entry_hash of the prior event, or None for the genesis event
    """

    collector: str
    action: str
    timestamp: str
    target: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    previous_hash: Optional[str] = None

    def _content(self) -> Dict[str, Any]:
        """The fields covered by the hash (everything except the derived entry_hash)."""
        return {
            "collector": self.collector,
            "action": self.action,
            "timestamp": self.timestamp,
            "target": self.target,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }

    def entry_hash(self) -> str:
        """SHA-256 over this event's canonical content. Deterministic."""
        return sha256_bytes(canonical_json(self._content()).encode("utf-8"))

    def to_dict(self) -> Dict[str, Any]:
        """Machine-readable form, including the derived entry_hash for external verify."""
        d = self._content()
        d["entry_hash"] = self.entry_hash()
        return d


class CustodyChain:
    """Append-only sequence of CustodyEvents with automatic hash linkage."""

    def __init__(self, events: Optional[List[CustodyEvent]] = None):
        self.events: List[CustodyEvent] = list(events or [])

    def append(
        self,
        collector: str,
        action: str,
        when: datetime,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> CustodyEvent:
        prev = self.events[-1].entry_hash() if self.events else None
        event = CustodyEvent(
            collector=collector,
            action=action,
            timestamp=to_iso(when),
            target=target,
            details=details,
            previous_hash=prev,
        )
        self.events.append(event)
        return event

    def to_list(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.events]


def verify_custody_chain(events: List[CustodyEvent]) -> Tuple[bool, Optional[int]]:
    """Verify hash linkage across the chain.

    Returns (ok, first_bad_index). Recomputes each event's entry_hash and checks that
    every event's previous_hash equals the recomputed hash of the one before it. If an
    interior event is altered, the mismatch surfaces at the *following* index.

    Note: tampering with the final event alone cannot be detected here (nothing links
    after it) — that is caught at the manifest level, whose hash covers all events.
    """
    expected_prev: Optional[str] = None
    for i, event in enumerate(events):
        if event.previous_hash != expected_prev:
            return False, i
        expected_prev = event.entry_hash()
    return True, None
