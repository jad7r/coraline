"""
Deterministic, machine-readable evidence manifest.

An EvidenceManifest records a set of evidence items — each with path, size, SHA-256,
file created/modified timestamps (when the filesystem provides them), and a collection
timestamp — plus a hash-linked chain of custody.

Serialization is canonical: keys are sorted, items are sorted by (path, sha256), and
whitespace is compact. The same inputs therefore always produce byte-identical output
and a stable ``manifest_hash()``. Any change to an item or a custody event changes that
hash, which is the tamper-detection primitive. Stdlib only — no network, AI, crypto, or
presentation dependencies.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.evidence._util import canonical_json, to_iso
from core.evidence.custody import CustodyChain, CustodyEvent, verify_custody_chain
from core.evidence.hashing import PathLike, sha256_bytes, sha256_file

MANIFEST_VERSION = "1"
HASH_ALGORITHM = "sha256"


@dataclass(frozen=True)
class EvidenceItem:
    """One preserved piece of evidence and its integrity metadata."""

    path: str
    size: int
    sha256: str
    collected_at: str                 # ISO-8601 UTC — when Coreline captured it
    created: Optional[str] = None     # ISO-8601 UTC — file birth time, if available
    modified: Optional[str] = None    # ISO-8601 UTC — file mtime, if available
    algorithm: str = HASH_ALGORITHM

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceItem":
        return cls(**d)


def build_evidence_item(path: PathLike, *, collected_when: datetime) -> EvidenceItem:
    """Hash a file and capture its integrity metadata.

    ``created`` is populated from the file's birth time when the platform exposes it
    (e.g. macOS ``st_birthtime``); otherwise it is left None ("when available").
    """
    p = Path(path)
    st = p.stat()
    modified = to_iso(datetime.fromtimestamp(st.st_mtime, tz=timezone.utc))
    created: Optional[str] = None
    birth = getattr(st, "st_birthtime", None)
    if birth:
        created = to_iso(datetime.fromtimestamp(birth, tz=timezone.utc))
    return EvidenceItem(
        path=str(path),
        size=st.st_size,
        sha256=sha256_file(p),
        collected_at=to_iso(collected_when),
        created=created,
        modified=modified,
    )


class EvidenceManifest:
    """A deterministic collection of evidence items plus a custody chain."""

    def __init__(
        self,
        incident_id: Optional[str],
        created_when: datetime,
        version: str = MANIFEST_VERSION,
    ):
        self.version = version
        self.incident_id = incident_id
        self.created_at = to_iso(created_when)
        self.items: List[EvidenceItem] = []
        self.chain = CustodyChain()

    # -- construction ------------------------------------------------------- #
    def add_item(self, item: EvidenceItem) -> None:
        self.items.append(item)

    def record_custody(
        self,
        collector: str,
        action: str,
        when: datetime,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> CustodyEvent:
        return self.chain.append(collector, action, when, target=target, details=details)

    # -- serialization ------------------------------------------------------ #
    def _sorted_items(self) -> List[EvidenceItem]:
        # Sort so add-order never affects the canonical output.
        return sorted(self.items, key=lambda i: (i.path, i.sha256))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "algorithm": HASH_ALGORITHM,
            "items": [i.to_dict() for i in self._sorted_items()],
            "custody": self.chain.to_list(),
        }

    def to_json(self, *, pretty: bool = False) -> str:
        if pretty:
            return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)
        return canonical_json(self.to_dict())

    def manifest_hash(self) -> str:
        """SHA-256 over the canonical manifest. Changes if any item/custody event changes."""
        return sha256_bytes(canonical_json(self.to_dict()).encode("utf-8"))

    def verify_custody(self):
        """(ok, first_bad_index) for the custody chain — see verify_custody_chain."""
        return verify_custody_chain(self.chain.events)

    # -- reconstruction ----------------------------------------------------- #
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceManifest":
        m = cls.__new__(cls)  # bypass __init__; we set canonical fields directly
        m.version = d["version"]
        m.incident_id = d.get("incident_id")
        m.created_at = d["created_at"]
        m.items = [
            EvidenceItem.from_dict({k: v for k, v in it.items() if k in EvidenceItem.__annotations__})
            for it in d.get("items", [])
        ]
        events = [
            CustodyEvent(
                collector=e["collector"],
                action=e["action"],
                timestamp=e["timestamp"],
                target=e.get("target"),
                details=e.get("details"),
                previous_hash=e.get("previous_hash"),
            )
            for e in d.get("custody", [])
        ]
        m.chain = CustodyChain(events)
        return m


def build_manifest(
    incident_id: Optional[str],
    paths: Sequence[PathLike],
    collector: str,
    when: datetime,
) -> EvidenceManifest:
    """Convenience: hash each path into an item, record a 'collected' custody event per
    item, and append a terminal 'manifest-sealed' event. Custody order follows ``paths``.
    """
    m = EvidenceManifest(incident_id, when)
    for p in paths:
        item = build_evidence_item(p, collected_when=when)
        m.add_item(item)
        m.record_custody(
            collector, "collected", when,
            target=item.sha256,
            details={"path": item.path, "size": item.size},
        )
    m.record_custody(collector, "manifest-sealed", when, target="manifest")
    return m
