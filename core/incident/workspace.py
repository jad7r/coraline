"""Incident workspace — Coreline's deterministic incident domain layer.

This owns incident **state** and an append-only **audit log**, and wires the
existing evidence and storage primitives for everything crypto-bearing:

  * evidence hashing + manifest .......... core.evidence (build_evidence_item, EvidenceManifest)
  * chain of custody ..................... core.evidence.custody
  * Ed25519 manifest signing/verify ...... core.evidence.integrity.signing
  * write-only artifact storage .......... core.storage.LocalFileBackend -> Receipt

The audit log is itself hash-linked using the SAME primitives the evidence layer uses
(``sha256_bytes`` over ``canonical_json``), so tampering with any interior entry is
detectable — the audit log is genuinely tamper-evident, not a plain text file.

Persistence layout, under ``<home>/<incident_id>/``:
    state.json      incident lifecycle + metadata
    audit.jsonl     hash-linked audit events (one JSON object per line)
    manifest.json   canonical evidence manifest (byte-stable)
    manifest.sig    base64 Ed25519 signature over manifest.json's bytes
    signer.json     verify key (base64) + fingerprint
    keys/signing.key  base64 Ed25519 seed, mode 0600  (demo store; prod = OS keychain)
    store/          LocalFileBackend root — deposited copies of evidence bytes
    report.md       generated PIR

All timestamps are UTC. Stdlib + core + PyNaCl only.
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from core.evidence._util import canonical_json, to_iso
from core.evidence.hashing import sha256_bytes, sha256_file
from core.evidence.manifest import EvidenceManifest, build_evidence_item
from core.evidence.integrity import signing
from core.storage.local import LocalFileBackend

# ---- constants --------------------------------------------------------------- #

SEVERITIES = ("SEV1", "SEV2", "SEV3", "SEV4", "SEV5")
OBSERVATION_DISPOSITIONS = ("OBSERVED", "SUSPECTED", "REFUTED", "INCONCLUSIVE")
OBSERVATION_AMENDMENT_TYPES = ("CORRECTION", "RETRACTION")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_PREFIX_RE = re.compile(r"^[0-9a-f]{12,63}$")

# Lifecycle states, in order. `declare` starts at OPEN; the first evidence advances
# to INVESTIGATING. Resolution/closure/sealing are explicit audited boundaries.
LIFECYCLE = (
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "ERADICATING",
    "RECOVERING",
    "RESOLVED",
    "CLOSED",
    "SEALED",
)

DEFAULT_HOME = "coreline-incidents"
CURRENT_POINTER = "CURRENT"

LEGACY_STATUS = {"DECLARED": "OPEN"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def new_incident_id(when: datetime) -> str:
    """INC-YYYYMMDD-XXXXXX — date for humans, 6 hex for uniqueness."""
    return f"INC-{when.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


def default_actor() -> str:
    return os.environ.get("CORELINE_ACTOR") or getpass.getuser()


def canonical_status(status: Optional[str]) -> str:
    """Normalize persisted lifecycle values from older Coreline workspaces."""
    raw = (status or "OPEN").upper()
    return LEGACY_STATUS.get(raw, raw)


# ---- errors ------------------------------------------------------------------ #

class WorkspaceError(Exception):
    """Operator-facing workspace error (bad state, missing incident, etc.)."""


# ---- audit log --------------------------------------------------------------- #

@dataclass(frozen=True)
class AuditEntry:
    seq: int
    timestamp: str
    actor: str
    action: str
    detail: Dict[str, Any]
    prev_hash: Optional[str]

    def _content(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }

    def entry_hash(self) -> str:
        return sha256_bytes(canonical_json(self._content()).encode("utf-8"))

    def to_dict(self) -> Dict[str, Any]:
        d = self._content()
        d["entry_hash"] = self.entry_hash()
        return d


def verify_audit(entries: List[AuditEntry]) -> Tuple[bool, Optional[int]]:
    """Recompute the hash linkage. Returns (ok, first_bad_seq)."""
    expected_prev: Optional[str] = None
    for e in entries:
        if e.prev_hash != expected_prev:
            return False, e.seq
        expected_prev = e.entry_hash()
    return True, None


# ---- quality gate ------------------------------------------------------------ #

@dataclass(frozen=True)
class Gate:
    key: str
    label: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class Observation:
    """One immutable investigative observation linked to incident evidence hashes."""

    observation_id: str
    incident_id: str
    text: str
    created_at: str
    creator: str
    disposition: str = "OBSERVED"
    evidence: Tuple[str, ...] = ()
    subject: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "observation_id": self.observation_id,
            "incident_id": self.incident_id,
            "text": self.text,
            "created_at": self.created_at,
            "creator": self.creator,
            "disposition": self.disposition,
            "evidence": list(self.evidence),
        }
        if self.subject:
            d["subject"] = self.subject
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Observation":
        return cls(
            observation_id=str(d["observation_id"]),
            incident_id=str(d["incident_id"]),
            text=str(d["text"]),
            created_at=str(d["created_at"]),
            creator=str(d["creator"]),
            disposition=str(d.get("disposition", "OBSERVED")).upper(),
            evidence=tuple(str(e).lower() for e in d.get("evidence", [])),
            subject=str(d["subject"]) if d.get("subject") else None,
        )

    def text_hash(self) -> str:
        return sha256_bytes(self.text.encode("utf-8"))

    def record_hash(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()).encode("utf-8"))


@dataclass(frozen=True)
class ObservationAmendment:
    """Append-only correction or retraction for an immutable observation."""

    amendment_id: str
    observation_id: str
    incident_id: str
    amendment_type: str
    created_at: str
    creator: str
    text: str
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "amendment_id": self.amendment_id,
            "observation_id": self.observation_id,
            "incident_id": self.incident_id,
            "amendment_type": self.amendment_type,
            "created_at": self.created_at,
            "creator": self.creator,
            "text": self.text,
        }
        if self.reason:
            d["reason"] = self.reason
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ObservationAmendment":
        return cls(
            amendment_id=str(d["amendment_id"]),
            observation_id=str(d["observation_id"]),
            incident_id=str(d["incident_id"]),
            amendment_type=str(d["amendment_type"]).upper(),
            created_at=str(d["created_at"]),
            creator=str(d["creator"]),
            text=str(d["text"]),
            reason=str(d["reason"]) if d.get("reason") else None,
        )

    def text_hash(self) -> str:
        return sha256_bytes(self.text.encode("utf-8"))

    def reason_hash(self) -> Optional[str]:
        return sha256_bytes(self.reason.encode("utf-8")) if self.reason else None

    def record_hash(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()).encode("utf-8"))


@dataclass(frozen=True)
class EffectiveObservation:
    """Deterministic current view of an immutable observation plus amendments."""

    observation: Observation
    amendments: Tuple[ObservationAmendment, ...]
    current_status: str
    current_text: str
    latest_correction: Optional[ObservationAmendment] = None
    retraction: Optional[ObservationAmendment] = None


# ---- the workspace ----------------------------------------------------------- #

@dataclass
class IncidentWorkspace:
    home: Path
    incident_id: str

    # in-memory state
    state: Dict[str, Any] = field(default_factory=dict)

    # -- paths ----------------------------------------------------------------- #
    @property
    def dir(self) -> Path:
        return self.home / self.incident_id

    @property
    def _state_path(self) -> Path:
        return self.dir / "state.json"

    @property
    def _audit_path(self) -> Path:
        return self.dir / "audit.jsonl"

    @property
    def _manifest_path(self) -> Path:
        return self.dir / "manifest.json"

    @property
    def _observations_path(self) -> Path:
        return self.dir / "observations.json"

    @property
    def _sig_path(self) -> Path:
        return self.dir / "manifest.sig"

    @property
    def _signer_path(self) -> Path:
        return self.dir / "signer.json"

    @property
    def _key_path(self) -> Path:
        return self.dir / "keys" / "signing.key"

    @property
    def _store(self) -> LocalFileBackend:
        return LocalFileBackend(self.dir / "store")

    @property
    def report_path(self) -> Path:
        return self.dir / "report.md"

    # -- home / current-pointer helpers ---------------------------------------- #
    @staticmethod
    def resolve_home(home: Optional[str] = None) -> Path:
        return Path(home or os.environ.get("CORELINE_HOME") or DEFAULT_HOME).resolve()

    @classmethod
    def _pointer_file(cls, home: Path) -> Path:
        return home / CURRENT_POINTER

    @classmethod
    def current_id(cls, home: Path) -> Optional[str]:
        p = cls._pointer_file(home)
        if p.exists():
            val = p.read_text(encoding="utf-8").strip()
            return val or None
        return None

    def _set_current(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self._pointer_file(self.home).write_text(self.incident_id, encoding="utf-8")

    def make_active(self) -> None:
        """Mark this incident as the active one (shared with the CLI's --current)."""
        self._set_current()

    @classmethod
    def list_incidents(cls, home: Path) -> List[str]:
        if not home.exists():
            return []
        return sorted(
            p.name for p in home.iterdir()
            if p.is_dir() and (p / "state.json").exists()
        )

    # -- construction ---------------------------------------------------------- #
    @classmethod
    def declare(
        cls,
        home: Path,
        *,
        title: str,
        severity: str,
        actor: str,
        when: Optional[datetime] = None,
    ) -> "IncidentWorkspace":
        severity = severity.upper()
        if severity not in SEVERITIES:
            raise WorkspaceError(
                f"invalid severity {severity!r}; choose one of {', '.join(SEVERITIES)}"
            )
        if not title.strip():
            raise WorkspaceError("title must not be empty")

        when = when or _now()
        incident_id = new_incident_id(when)
        ws = cls(home=home, incident_id=incident_id)
        ws.dir.mkdir(parents=True, exist_ok=True)
        (ws.dir / "keys").mkdir(exist_ok=True)

        # Generate the incident signing key (Ed25519) and persist the seed 0600.
        sk, vk = signing.generate_signing_keypair()
        ws._write_key(sk)
        ws._signer_path.write_text(
            json.dumps(
                {
                    "verify_key": signing.encode_verify_key(vk),
                    "fingerprint": signing.key_fingerprint(vk),
                    "algorithm": "ed25519",
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        ws.state = {
            "incident_id": incident_id,
            "title": title.strip(),
            "severity": severity,
            "status": "OPEN",
            "created_at": to_iso(when),
            "updated_at": to_iso(when),
            "actor": actor,
            "evidence_count": 0,
        }
        ws._save_state()
        # Seed the audit log + an (empty) signed manifest so verification works from t0.
        ws._append_audit(actor, "incident-declared",
                         {"title": title.strip(), "severity": severity}, when)
        ws._current_manifest_for_signing = EvidenceManifest(incident_id, when)
        ws._reseal_manifest(actor, when)
        ws._set_current()
        return ws

    @classmethod
    def load(cls, home: Path, incident_id: str) -> "IncidentWorkspace":
        ws = cls(home=home, incident_id=incident_id)
        if not ws._state_path.exists():
            raise WorkspaceError(f"no such incident: {incident_id} (under {home})")
        ws.state = json.loads(ws._state_path.read_text(encoding="utf-8"))
        ws.state["status"] = canonical_status(ws.state.get("status"))
        return ws

    @classmethod
    def load_current(cls, home: Path) -> "IncidentWorkspace":
        cur = cls.current_id(home)
        if not cur:
            raise WorkspaceError(
                "no active incident — run `coreline declare` first (or pass --id)"
            )
        return cls.load(home, cur)

    # -- key handling ---------------------------------------------------------- #
    def _write_key(self, sk: "signing.nacl.signing.SigningKey") -> None:  # type: ignore[name-defined]
        seed = signing.encode_signing_key(sk)  # 32-byte seed
        self._key_path.write_text(base64.b64encode(seed).decode("ascii"), encoding="utf-8")
        try:
            os.chmod(self._key_path, 0o600)
        except OSError:
            pass  # best-effort on platforms without POSIX perms

    def _read_signing_key(self):
        raw = base64.b64decode(self._key_path.read_text(encoding="utf-8").strip())
        return signing.decode_signing_key(raw)

    def _read_verify_key(self):
        info = json.loads(self._signer_path.read_text(encoding="utf-8"))
        return signing.decode_verify_key(info["verify_key"]), info

    # -- state ----------------------------------------------------------------- #
    def _save_state(self) -> None:
        self.state["status"] = canonical_status(self.state.get("status"))
        self._state_path.write_text(
            json.dumps(self.state, indent=2, sort_keys=True), encoding="utf-8"
        )

    def _status_index(self, status: Optional[str] = None) -> int:
        cur = canonical_status(status or self.state.get("status"))
        if cur not in LIFECYCLE:
            raise WorkspaceError(f"invalid persisted lifecycle status: {cur}")
        return LIFECYCLE.index(cur)

    def _advance_status(self, target: str, when: datetime) -> None:
        """Advance the lifecycle forward only (never regress)."""
        target = canonical_status(target)
        if target not in LIFECYCLE:
            raise WorkspaceError(f"invalid lifecycle target: {target}")
        cur = canonical_status(self.state.get("status"))
        if self._status_index(target) > self._status_index(cur):
            self.state["status"] = target
            self.state["updated_at"] = to_iso(when)

    def update_metadata(
        self,
        actor: str,
        *,
        title: Optional[str] = None,
        severity: Optional[str] = None,
        description: Optional[str] = None,
        when: Optional[datetime] = None,
    ) -> None:
        """Update mutable incident metadata with an audit event."""
        if self.is_closed:
            raise WorkspaceError(
                f"incident {self.incident_id} is {canonical_status(self.state.get('status')).lower()}; "
                "metadata is locked"
            )
        updates: Dict[str, Any] = {}
        if title is not None:
            clean_title = title.strip()
            if not clean_title:
                raise WorkspaceError("title must not be empty")
            updates["title"] = clean_title
        if severity is not None:
            clean_severity = severity.upper()
            if clean_severity not in SEVERITIES:
                raise WorkspaceError(
                    f"invalid severity {clean_severity!r}; choose one of {', '.join(SEVERITIES)}"
                )
            updates["severity"] = clean_severity
        if description is not None:
            updates["description"] = description.strip()
        changes = {
            key: {"from": self.state.get(key), "to": value}
            for key, value in updates.items()
            if self.state.get(key) != value
        }
        if not changes:
            return
        when = when or _now()
        for key, change in changes.items():
            self.state[key] = change["to"]
        self.state["updated_at"] = to_iso(when)
        self._save_state()
        self._append_audit(
            actor,
            "incident-metadata-updated",
            {"changes": changes},
            when,
        )

    def transition(
        self,
        target: str,
        actor: str,
        note: str = "",
        when: Optional[datetime] = None,
    ) -> None:
        """Advance incident lifecycle with an explicit audit entry."""
        if self.is_closed:
            raise WorkspaceError(f"incident {self.incident_id} is closed; lifecycle is locked")
        target = canonical_status(target)
        if target not in LIFECYCLE:
            raise WorkspaceError(f"invalid lifecycle target: {target}")
        if target in ("OPEN", "CLOSED", "SEALED"):
            raise WorkspaceError(f"cannot transition incident to {target}")
        cur = canonical_status(self.state.get("status"))
        if self._status_index(target) <= self._status_index(cur):
            raise WorkspaceError(f"cannot move lifecycle from {cur} to {target}")
        if target == "RESOLVED":
            blocking = [g for g in self.gates() if g.key != "report" and not g.passed]
            if blocking:
                keys = ", ".join(g.key for g in blocking)
                raise WorkspaceError(f"cannot resolve incident; unmet gates: {keys}")
        when = when or _now()
        self._advance_status(target, when)
        self._save_state()
        self._append_audit(
            actor,
            "lifecycle-transition",
            {"from": cur, "to": target, "note": note},
            when,
        )

    # -- audit ----------------------------------------------------------------- #
    def _load_audit(self) -> List[AuditEntry]:
        entries: List[AuditEntry] = []
        if not self._audit_path.exists():
            return entries
        for line in self._audit_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            entries.append(AuditEntry(
                seq=d["seq"], timestamp=d["timestamp"], actor=d["actor"],
                action=d["action"], detail=d.get("detail", {}),
                prev_hash=d.get("prev_hash"),
            ))
        return entries

    def _append_audit(self, actor: str, action: str, detail: Dict[str, Any],
                      when: datetime) -> AuditEntry:
        entries = self._load_audit()
        prev = entries[-1].entry_hash() if entries else None
        entry = AuditEntry(
            seq=len(entries) + 1,
            timestamp=to_iso(when),
            actor=actor,
            action=action,
            detail=detail,
            prev_hash=prev,
        )
        with self._audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
        return entry

    def audit_entries(self) -> List[AuditEntry]:
        return self._load_audit()

    # -- demo / tamper controls ------------------------------------------------ #
    @property
    def _audit_backup(self) -> Path:
        return self.dir / "audit.jsonl.orig"

    def simulate_tamper(self) -> bool:
        """DEMO ONLY: forge the first audit entry so the hash chain breaks.

        Snapshots the clean log to ``audit.jsonl.orig`` once (so it can be repaired),
        then rewrites seq-1's ``actor`` — valid JSON, but its entry_hash no longer
        matches seq-2's ``prev_hash``, so ``verify()`` reports the chain broken.
        Returns True if a tamper was applied.
        """
        if not self._audit_path.exists():
            return False
        if not self._audit_backup.exists():
            self._audit_backup.write_text(
                self._audit_path.read_text(encoding="utf-8"), encoding="utf-8")
        lines = self._audit_path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return False
        d = json.loads(lines[0])
        d["actor"] = "mallory@evil.tld"  # forged responder identity
        lines[0] = json.dumps(d, sort_keys=True)
        self._audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True

    def repair_audit(self) -> bool:
        """DEMO ONLY: restore the pre-tamper audit snapshot. Returns True if repaired."""
        if self._audit_backup.exists():
            self._audit_path.write_text(
                self._audit_backup.read_text(encoding="utf-8"), encoding="utf-8")
            self._audit_backup.unlink()
            return True
        return False

    # -- closure --------------------------------------------------------------- #
    @property
    def is_closed(self) -> bool:
        return canonical_status(self.state.get("status")) in ("CLOSED", "SEALED") or bool(
            self.state.get("closed")
        )

    @property
    def is_sealed(self) -> bool:
        return canonical_status(self.state.get("status")) == "SEALED" or bool(
            self.state.get("sealed")
        )

    def _evidence_intake_locked(self) -> bool:
        return self.is_closed or self._status_index() >= self._status_index("RESOLVED")

    def close_incident(
        self,
        actor: str,
        when: Optional[datetime] = None,
        *,
        force: bool = False,
        reason: Optional[str] = None,
    ) -> str:
        """Close the incident: generate the final signed PIR and lock the lifecycle.

        Generates the PIR (which seals the current manifest state and advances to
        RESOLVED when gates are green), then marks the incident CLOSED. After this the
        CLI/GUI treat evidence intake as locked.
        """
        if self.is_sealed:
            raise WorkspaceError(f"incident {self.incident_id} is sealed")
        if self.is_closed:
            raise WorkspaceError(f"incident {self.incident_id} is already closed")
        when = when or _now()
        blocking = [g for g in self.gates() if g.key != "report" and not g.passed]
        if blocking and not force:
            keys = ", ".join(g.key for g in blocking)
            raise WorkspaceError(
                f"cannot close incident; unmet pre-closure gates: {keys}"
            )
        reason_text = (reason or "").strip()
        if blocking and not reason_text:
            raise WorkspaceError("forced closure requires a reason")
        if blocking:
            self._append_audit(
                actor,
                "closure-override",
                {"reason": reason_text, "blocking_gates": [g.key for g in blocking]},
                when,
            )
        report_md = self.generate_report(actor, when)
        self.state["status"] = "CLOSED"
        self.state["closed"] = True
        if blocking:
            self.state["closure_forced"] = True
            self.state["closure_reason"] = reason_text
        self.state["updated_at"] = to_iso(when)
        self._save_state()
        self._append_audit(actor, "incident-closed",
                          {"final_status": "CLOSED", "forced": bool(blocking)}, when)
        return report_md

    def seal_incident(self, actor: str, when: Optional[datetime] = None) -> None:
        """Seal a closed incident after all integrity gates verify green."""
        if self.is_sealed:
            raise WorkspaceError(f"incident {self.incident_id} is already sealed")
        if canonical_status(self.state.get("status")) != "CLOSED":
            raise WorkspaceError("incident must be closed before it can be sealed")
        blocking = [g for g in self.gates() if not g.passed]
        if blocking:
            keys = ", ".join(g.key for g in blocking)
            raise WorkspaceError(f"cannot seal incident; unmet gates: {keys}")
        when = when or _now()
        cur = canonical_status(self.state.get("status"))
        self.state["status"] = "SEALED"
        self.state["sealed"] = True
        self.state["updated_at"] = to_iso(when)
        self._save_state()
        self._append_audit(
            actor,
            "incident-sealed",
            {"from": cur, "to": "SEALED"},
            when,
        )

    def evidence_items(self):
        """Evidence items in canonical order (for display)."""
        m = self._load_manifest()
        return sorted(m.items, key=lambda i: (i.collected_at, i.path))

    def evidence_shas(self) -> set:
        """SHA-256s already in the manifest — used to make uploads idempotent."""
        return {it.sha256 for it in self._load_manifest().items}

    # -- observations ---------------------------------------------------------- #
    def _load_observation_store(self) -> Tuple[List[Observation], List[ObservationAmendment]]:
        if not self._observations_path.exists():
            return [], []
        data = json.loads(self._observations_path.read_text(encoding="utf-8"))
        observations = [Observation.from_dict(d) for d in data.get("observations", [])]
        amendments = [
            ObservationAmendment.from_dict(d)
            for d in data.get("amendments", [])
        ]
        return (
            sorted(observations, key=lambda o: (o.created_at, o.observation_id)),
            sorted(amendments, key=lambda a: (a.created_at, a.amendment_id)),
        )

    def _load_observations(self) -> List[Observation]:
        observations, _ = self._load_observation_store()
        return observations

    def _load_observation_amendments(self) -> List[ObservationAmendment]:
        _, amendments = self._load_observation_store()
        return amendments

    def _save_observation_store(
        self,
        observations: List[Observation],
        amendments: List[ObservationAmendment],
    ) -> None:
        ordered = sorted(observations, key=lambda o: (o.created_at, o.observation_id))
        ordered_amendments = sorted(amendments, key=lambda a: (a.created_at, a.amendment_id))
        payload = {
            "version": "1",
            "incident_id": self.incident_id,
            "observations": [o.to_dict() for o in ordered],
            "amendments": [a.to_dict() for a in ordered_amendments],
        }
        self._observations_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )

    def _save_observations(self, observations: List[Observation]) -> None:
        _, amendments = self._load_observation_store()
        self._save_observation_store(observations, amendments)

    def _save_observation_amendments(self, amendments: List[ObservationAmendment]) -> None:
        observations, _ = self._load_observation_store()
        self._save_observation_store(observations, amendments)

    def _resolve_evidence_ref(self, ref: str) -> str:
        value = ref.strip().lower()
        if not value:
            raise WorkspaceError("evidence reference must not be empty")
        shas = sorted(self.evidence_shas())
        if SHA256_RE.match(value):
            if value in shas:
                return value
            raise WorkspaceError(f"evidence not found in incident manifest: {ref}")
        if SHA256_PREFIX_RE.match(value):
            matches = [sha for sha in shas if sha.startswith(value)]
            if len(matches) == 1:
                return matches[0]
            if matches:
                raise WorkspaceError(f"ambiguous evidence reference: {ref}")
        raise WorkspaceError(f"invalid evidence reference: {ref}")

    def observations(self) -> List[Observation]:
        return self._load_observations()

    def observation_amendments(
        self,
        observation_id: Optional[str] = None,
    ) -> List[ObservationAmendment]:
        amendments = self._load_observation_amendments()
        if observation_id:
            amendments = [a for a in amendments if a.observation_id == observation_id]
        return amendments

    def observation_is_retracted(self, observation_id: str) -> bool:
        return any(
            a.amendment_type == "RETRACTION"
            for a in self.observation_amendments(observation_id)
        )

    def effective_observation(self, observation_id: str) -> EffectiveObservation:
        obs = self.observation(observation_id)
        amendments = tuple(self.observation_amendments(observation_id))
        latest_correction: Optional[ObservationAmendment] = None
        retraction: Optional[ObservationAmendment] = None
        for amendment in amendments:
            if amendment.amendment_type == "RETRACTION" and retraction is None:
                retraction = amendment
            elif amendment.amendment_type == "CORRECTION" and retraction is None:
                latest_correction = amendment
        current_status = "RETRACTED" if retraction else obs.disposition
        current_text = retraction.text if retraction else (
            latest_correction.text if latest_correction else obs.text
        )
        return EffectiveObservation(
            observation=obs,
            amendments=amendments,
            current_status=current_status,
            current_text=current_text,
            latest_correction=latest_correction,
            retraction=retraction,
        )

    def observation(self, observation_id: str) -> Observation:
        for obs in self._load_observations():
            if obs.observation_id == observation_id:
                return obs
        raise WorkspaceError(f"observation not found: {observation_id}")

    def add_observation(
        self,
        text: str,
        actor: str,
        evidence_refs: Optional[List[str]] = None,
        disposition: str = "OBSERVED",
        subject: Optional[str] = None,
        when: Optional[datetime] = None,
    ) -> Observation:
        if self.is_closed:
            raise WorkspaceError(
                f"incident {self.incident_id} is {canonical_status(self.state.get('status')).lower()}; "
                "observations are locked"
            )
        clean_text = text.strip()
        if not clean_text:
            raise WorkspaceError("observation text must not be empty")
        disposition = disposition.upper()
        if disposition not in OBSERVATION_DISPOSITIONS:
            raise WorkspaceError(
                f"invalid observation disposition {disposition!r}; choose one of "
                f"{', '.join(OBSERVATION_DISPOSITIONS)}"
            )
        evidence = tuple(
            sorted({self._resolve_evidence_ref(ref) for ref in (evidence_refs or [])})
        )
        when = when or _now()
        observation_id = f"OBS-{uuid.uuid4().hex[:12].upper()}"
        existing = self._load_observations()
        if any(o.observation_id == observation_id for o in existing):
            raise WorkspaceError(f"duplicate observation id generated: {observation_id}")
        obs = Observation(
            observation_id=observation_id,
            incident_id=self.incident_id,
            text=clean_text,
            created_at=to_iso(when),
            creator=actor,
            disposition=disposition,
            evidence=evidence,
            subject=subject.strip() if subject and subject.strip() else None,
        )
        self._save_observations(existing + [obs])
        self.state["observation_count"] = len(existing) + 1
        self.state["updated_at"] = to_iso(when)
        self._save_state()
        self._append_audit(
            actor,
            "observation-created",
            {
                "observation_id": obs.observation_id,
                "incident_id": self.incident_id,
                "created_at": obs.created_at,
                "creator": obs.creator,
                "disposition": obs.disposition,
                "evidence": list(obs.evidence),
                "subject": obs.subject,
                "record_hash": obs.record_hash(),
                "text_hash": obs.text_hash(),
                "text": obs.text,
            },
            when,
        )
        return obs

    def correct_observation(
        self,
        observation_id: str,
        correction: str,
        actor: str,
        reason: Optional[str] = None,
        when: Optional[datetime] = None,
    ) -> ObservationAmendment:
        if self.is_closed:
            raise WorkspaceError(
                f"incident {self.incident_id} is {canonical_status(self.state.get('status')).lower()}; "
                "observations are locked"
            )
        self.observation(observation_id)
        if self.observation_is_retracted(observation_id):
            raise WorkspaceError(f"observation {observation_id} is retracted")
        clean = correction.strip()
        if not clean:
            raise WorkspaceError("correction text must not be empty")
        reason_text = reason.strip() if reason and reason.strip() else None
        when = when or _now()
        amendments = self._load_observation_amendments()
        amendment = ObservationAmendment(
            amendment_id=f"OAM-{uuid.uuid4().hex[:12].upper()}",
            observation_id=observation_id,
            incident_id=self.incident_id,
            amendment_type="CORRECTION",
            created_at=to_iso(when),
            creator=actor,
            text=clean,
            reason=reason_text,
        )
        if any(a.amendment_id == amendment.amendment_id for a in amendments):
            raise WorkspaceError(f"duplicate observation amendment id generated: {amendment.amendment_id}")
        self._save_observation_amendments(amendments + [amendment])
        self.state["observation_amendment_count"] = len(amendments) + 1
        self.state["updated_at"] = to_iso(when)
        self._save_state()
        self._append_audit(
            actor,
            "observation-corrected",
            {
                "amendment_id": amendment.amendment_id,
                "observation_id": observation_id,
                "incident_id": self.incident_id,
                "amendment_type": amendment.amendment_type,
                "created_at": amendment.created_at,
                "creator": amendment.creator,
                "record_hash": amendment.record_hash(),
                "text_hash": amendment.text_hash(),
                "reason_hash": amendment.reason_hash(),
                "correction": amendment.text,
                "reason": amendment.reason,
            },
            when,
        )
        return amendment

    def retract_observation(
        self,
        observation_id: str,
        reason: str,
        actor: str,
        when: Optional[datetime] = None,
    ) -> ObservationAmendment:
        if self.is_closed:
            raise WorkspaceError(
                f"incident {self.incident_id} is {canonical_status(self.state.get('status')).lower()}; "
                "observations are locked"
            )
        self.observation(observation_id)
        if self.observation_is_retracted(observation_id):
            raise WorkspaceError(f"observation {observation_id} is already retracted")
        reason_text = reason.strip()
        if not reason_text:
            raise WorkspaceError("retraction reason must not be empty")
        when = when or _now()
        amendments = self._load_observation_amendments()
        amendment = ObservationAmendment(
            amendment_id=f"OAM-{uuid.uuid4().hex[:12].upper()}",
            observation_id=observation_id,
            incident_id=self.incident_id,
            amendment_type="RETRACTION",
            created_at=to_iso(when),
            creator=actor,
            text=reason_text,
        )
        if any(a.amendment_id == amendment.amendment_id for a in amendments):
            raise WorkspaceError(f"duplicate observation amendment id generated: {amendment.amendment_id}")
        self._save_observation_amendments(amendments + [amendment])
        self.state["observation_amendment_count"] = len(amendments) + 1
        self.state["updated_at"] = to_iso(when)
        self._save_state()
        self._append_audit(
            actor,
            "observation-retracted",
            {
                "amendment_id": amendment.amendment_id,
                "observation_id": observation_id,
                "incident_id": self.incident_id,
                "amendment_type": amendment.amendment_type,
                "created_at": amendment.created_at,
                "creator": amendment.creator,
                "record_hash": amendment.record_hash(),
                "reason_hash": amendment.text_hash(),
                "reason": amendment.text,
            },
            when,
        )
        return amendment

    def verify_observations(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        try:
            observations, amendments = self._load_observation_store()
        except Exception as exc:
            return False, [f"observations unreadable: {exc}"]
        seen = set()
        try:
            evidence_shas = self.evidence_shas()
        except Exception as exc:
            return False, [f"evidence manifest unreadable: {exc}"]
        audits = self._load_audit()
        observation_events = [
            e for e in audits
            if e.action == "observation-created"
            and e.detail.get("incident_id") == self.incident_id
        ]
        amendment_events = [
            e for e in audits
            if e.action in ("observation-corrected", "observation-retracted")
            and e.detail.get("incident_id") == self.incident_id
        ]
        observations_by_id = {o.observation_id: o for o in observations}
        amendments_by_id = {a.amendment_id: a for a in amendments}
        for obs in observations:
            if obs.observation_id in seen:
                errors.append(f"{obs.observation_id}: duplicate observation id")
            seen.add(obs.observation_id)
            if obs.incident_id != self.incident_id:
                errors.append(f"{obs.observation_id}: incident id mismatch")
            if not obs.text.strip():
                errors.append(f"{obs.observation_id}: empty observation text")
            if obs.disposition not in OBSERVATION_DISPOSITIONS:
                errors.append(f"{obs.observation_id}: invalid disposition")
            for evidence in obs.evidence:
                if evidence not in evidence_shas:
                    errors.append(f"{obs.observation_id}: missing evidence {evidence}")
            matching_audit = any(
                e.action == "observation-created"
                and e.detail.get("observation_id") == obs.observation_id
                and e.detail.get("incident_id") == self.incident_id
                and e.actor == obs.creator
                and e.timestamp == obs.created_at
                and e.detail.get("creator") == obs.creator
                and e.detail.get("created_at") == obs.created_at
                and e.detail.get("disposition") == obs.disposition
                and e.detail.get("subject") == obs.subject
                and e.detail.get("record_hash") == obs.record_hash()
                and e.detail.get("text_hash") == obs.text_hash()
                and sorted(e.detail.get("evidence", [])) == list(obs.evidence)
                for e in observation_events
            )
            if not matching_audit:
                errors.append(f"{obs.observation_id}: missing matching audit event")
        for event in observation_events:
            observation_id = event.detail.get("observation_id")
            obs = observations_by_id.get(observation_id)
            if obs is None:
                errors.append(f"{observation_id}: audit event has no observation record")
            elif event.detail.get("record_hash") != obs.record_hash():
                errors.append(f"{observation_id}: audit event hash mismatch")
        observation_ids = {o.observation_id for o in observations}
        amendment_ids = set()
        retracted = set()
        for amendment in amendments:
            if amendment.amendment_id in amendment_ids:
                errors.append(f"{amendment.amendment_id}: duplicate amendment id")
            amendment_ids.add(amendment.amendment_id)
            if amendment.incident_id != self.incident_id:
                errors.append(f"{amendment.amendment_id}: incident id mismatch")
            if amendment.observation_id not in observation_ids:
                errors.append(f"{amendment.amendment_id}: missing observation {amendment.observation_id}")
            if amendment.amendment_type not in OBSERVATION_AMENDMENT_TYPES:
                errors.append(f"{amendment.amendment_id}: invalid amendment type")
            if not amendment.text.strip():
                errors.append(f"{amendment.amendment_id}: empty amendment text")
            if amendment.amendment_type == "RETRACTION":
                if amendment.observation_id in retracted:
                    errors.append(f"{amendment.amendment_id}: duplicate retraction")
                retracted.add(amendment.observation_id)
                matching_audit = any(
                    e.action == "observation-retracted"
                    and e.detail.get("amendment_id") == amendment.amendment_id
                    and e.detail.get("observation_id") == amendment.observation_id
                    and e.detail.get("incident_id") == self.incident_id
                    and e.actor == amendment.creator
                    and e.timestamp == amendment.created_at
                    and e.detail.get("amendment_type") == amendment.amendment_type
                    and e.detail.get("creator") == amendment.creator
                    and e.detail.get("created_at") == amendment.created_at
                    and e.detail.get("record_hash") == amendment.record_hash()
                    and e.detail.get("reason_hash") == amendment.text_hash()
                    for e in amendment_events
                )
            else:
                if amendment.observation_id in retracted:
                    errors.append(f"{amendment.amendment_id}: correction after retraction")
                matching_audit = any(
                    e.action == "observation-corrected"
                    and e.detail.get("amendment_id") == amendment.amendment_id
                    and e.detail.get("observation_id") == amendment.observation_id
                    and e.detail.get("incident_id") == self.incident_id
                    and e.actor == amendment.creator
                    and e.timestamp == amendment.created_at
                    and e.detail.get("amendment_type") == amendment.amendment_type
                    and e.detail.get("creator") == amendment.creator
                    and e.detail.get("created_at") == amendment.created_at
                    and e.detail.get("record_hash") == amendment.record_hash()
                    and e.detail.get("text_hash") == amendment.text_hash()
                    and e.detail.get("reason_hash") == amendment.reason_hash()
                    for e in amendment_events
                )
            if not matching_audit:
                errors.append(f"{amendment.amendment_id}: missing matching audit event")
        for event in amendment_events:
            amendment_id = event.detail.get("amendment_id")
            amendment = amendments_by_id.get(amendment_id)
            if amendment is None:
                errors.append(f"{amendment_id}: audit event has no amendment record")
            elif event.detail.get("record_hash") != amendment.record_hash():
                errors.append(f"{amendment_id}: audit event hash mismatch")
        return not errors, errors

    # -- evidence + manifest --------------------------------------------------- #
    def _load_manifest(self) -> EvidenceManifest:
        if self._manifest_path.exists():
            return EvidenceManifest.from_dict(
                json.loads(self._manifest_path.read_text(encoding="utf-8"))
            )
        return EvidenceManifest(self.incident_id, _now())

    def _reseal_manifest(self, actor: str, when: datetime) -> str:
        """Persist the current manifest canonically and (re)sign its bytes. Returns hash."""
        manifest = self._current_manifest_for_signing
        canonical = manifest.to_json(pretty=False)
        self._manifest_path.write_text(canonical, encoding="utf-8")
        sk = self._read_signing_key()
        sig = signing.sign(canonical.encode("utf-8"), sk)
        self._sig_path.write_text(base64.b64encode(sig).decode("ascii"), encoding="utf-8")
        return manifest.manifest_hash()

    # set transiently by add_evidence / declare before calling _reseal_manifest
    _current_manifest_for_signing: EvidenceManifest = field(default=None, repr=False)  # type: ignore[assignment]

    def add_evidence(
        self,
        file_path: str,
        note: str,
        actor: str,
        when: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        if self._evidence_intake_locked():
            raise WorkspaceError(
                f"incident {self.incident_id} is {canonical_status(self.state.get('status')).lower()}; "
                "evidence intake is locked"
            )
        when = when or _now()
        src = Path(file_path)
        if not src.exists() or not src.is_file():
            raise WorkspaceError(f"evidence file not found: {file_path}")

        # 1) Hash + capture integrity metadata via the mature core.
        item = build_evidence_item(src, collected_when=when)

        # 2) Deposit an immutable copy of the bytes through the write-only backend.
        data = src.read_bytes()
        object_name = f"{item.sha256}/{src.name}"
        receipt = self._store.put_object(object_name, data, stored_when=when,
                                         content_type="application/octet-stream")

        # 3) Rebuild the manifest (append item + custody), then re-sign it.
        manifest = self._load_manifest()
        manifest.add_item(item)
        manifest.record_custody(
            actor, "collected", when,
            target=item.sha256,
            details={"path": item.path, "size": item.size, "note": note,
                     "stored_uri": receipt.uri},
        )
        manifest.record_custody(actor, "manifest-sealed", when, target="manifest")
        self._current_manifest_for_signing = manifest
        manifest_hash = self._reseal_manifest(actor, when)

        # 4) State + audit.
        self.state["evidence_count"] = len(manifest.items)
        self._advance_status("INVESTIGATING", when)
        self._save_state()
        self._append_audit(
            actor, "evidence-added",
            {"sha256": item.sha256, "size": item.size, "file": src.name,
             "note": note, "manifest_hash": manifest_hash, "stored_uri": receipt.uri},
            when,
        )
        return {
            "sha256": item.sha256,
            "size": item.size,
            "receipt": receipt,
            "manifest_hash": manifest_hash,
            "evidence_count": len(manifest.items),
        }

    # -- verification ---------------------------------------------------------- #
    def verify(self) -> Dict[str, Any]:
        """Full integrity check: manifest signature, custody chain, audit chain, storage."""
        result: Dict[str, Any] = {
            "manifest_signature": False,
            "custody_chain": False,
            "audit_chain": False,
            "storage_artifacts": False,
            "fingerprint": None,
            "manifest_hash": None,
            "custody_bad_index": None,
            "audit_bad_seq": None,
            "storage_missing": [],
            "storage_bad_hash": [],
            "storage_unverifiable": [],
            "observations": True,
            "observation_errors": [],
        }
        manifest = None
        if self._manifest_path.exists() and self._sig_path.exists():
            # Fail closed: any error in reading/decoding/parsing a tampered manifest
            # yields an invalid result, never an exception to the caller.
            try:
                canonical = self._manifest_path.read_text(encoding="utf-8")
                sig = base64.b64decode(self._sig_path.read_text(encoding="utf-8").strip())
                vk, info = self._read_verify_key()
                result["fingerprint"] = info.get("fingerprint")
                result["manifest_signature"] = signing.verify(
                    canonical.encode("utf-8"), sig, vk
                )
            except Exception:
                result["manifest_signature"] = False
            try:
                manifest = self._load_manifest()
                result["manifest_hash"] = manifest.manifest_hash()
                ok, bad = manifest.verify_custody()
                result["custody_chain"] = ok
                result["custody_bad_index"] = bad
            except Exception:
                result["custody_chain"] = False
        if manifest is not None:
            storage = self._verify_storage_artifacts(manifest)
            result.update(storage)
        ok, bad_seq = verify_audit(self._load_audit())
        result["audit_chain"] = ok
        result["audit_bad_seq"] = bad_seq
        observations_ok, observation_errors = self.verify_observations()
        result["observations"] = observations_ok
        result["observation_errors"] = observation_errors
        return result

    def _verify_storage_artifacts(self, manifest: EvidenceManifest) -> Dict[str, Any]:
        missing: List[str] = []
        bad_hash: List[str] = []
        unverifiable: List[str] = []
        stored_uris: Dict[str, str] = {}

        for event in manifest.chain.events:
            if event.action != "collected" or not event.target:
                continue
            details = event.details or {}
            uri = details.get("stored_uri")
            if uri:
                stored_uris[event.target] = str(uri)

        for item in manifest.items:
            uri = stored_uris.get(item.sha256)
            if not uri:
                unverifiable.append(f"{item.sha256}: no stored_uri")
                continue
            parsed = urlparse(uri)
            if parsed.scheme != "file":
                unverifiable.append(f"{item.sha256}: unsupported uri {uri}")
                continue
            path = Path(unquote(parsed.path))
            if not path.exists() or not path.is_file():
                missing.append(uri)
                continue
            actual = sha256_file(path)
            if actual != item.sha256:
                bad_hash.append(f"{uri}: expected {item.sha256}, got {actual}")

        return {
            "storage_artifacts": not missing and not bad_hash and not unverifiable,
            "storage_missing": missing,
            "storage_bad_hash": bad_hash,
            "storage_unverifiable": unverifiable,
        }

    # -- quality gates --------------------------------------------------------- #
    def gates(self) -> List[Gate]:
        v = self.verify()
        n_items = int(self.state.get("evidence_count", 0))
        report_exists = self.report_path.exists()
        return [
            Gate("metadata", "Incident metadata complete",
                 bool(self.state.get("title") and self.state.get("severity")),
                 f"{self.state.get('severity')} · {self.state.get('title','')[:40]}"),
            Gate("evidence", "At least one evidence item", n_items >= 1,
                 f"{n_items} item(s)"),
            Gate("custody", "Chain of custody intact", v["custody_chain"],
                 "verified" if v["custody_chain"] else f"broken @ {v['custody_bad_index']}"),
            Gate("signature", "Manifest signature valid", v["manifest_signature"],
                 v["fingerprint"] or "no signer"),
            Gate("audit", "Audit log tamper-evident", v["audit_chain"],
                 "verified" if v["audit_chain"] else f"broken @ seq {v['audit_bad_seq']}"),
            Gate("storage", "Stored evidence artifacts present", v["storage_artifacts"],
                 "verified" if v["storage_artifacts"]
                 else f"{len(v['storage_missing'])} missing, "
                      f"{len(v['storage_bad_hash'])} bad hash, "
                      f"{len(v['storage_unverifiable'])} unverifiable"),
            Gate("observations", "Observations reference valid evidence", v["observations"],
                 "verified" if v["observations"]
                 else f"{len(v['observation_errors'])} issue(s)"),
            Gate("report", "PIR generated", report_exists,
                 "present" if report_exists else "not yet generated"),
        ]

    # -- report (PIR) ---------------------------------------------------------- #
    def generate_report(self, actor: str, when: Optional[datetime] = None) -> str:
        if self.is_closed:
            raise WorkspaceError(
                f"incident {self.incident_id} is {canonical_status(self.state.get('status')).lower()}; "
                "report generation is locked"
            )
        when = when or _now()
        v = self.verify()
        manifest = self._load_manifest()
        gates = self.gates()
        blocking = [g for g in gates if g.key != "report" and not g.passed]
        # Advance the lifecycle before composing so the report reflects final status.
        if not blocking and self._status_index() < self._status_index("RESOLVED"):
            self.transition(
                "RESOLVED",
                actor,
                note="PIR generated with pre-closure gates green",
                when=when,
            )

        lines: List[str] = []
        S = self.state
        lines.append(f"# Post-Incident Report — {S['incident_id']}")
        lines.append("")
        lines.append(f"**Title:** {S['title']}  ")
        lines.append(f"**Severity:** {S['severity']}  ")
        lines.append(f"**Status:** {S['status']}  ")
        lines.append(f"**Declared:** {S['created_at']}  ")
        lines.append(f"**Report generated:** {to_iso(when)}  ")
        lines.append(f"**Lead:** {S.get('actor','')}  ")
        lines.append("")
        lines.append("## Integrity attestation")
        lines.append("")
        lines.append(f"- Evidence manifest hash: `{v['manifest_hash']}`")
        lines.append(f"- Signing key fingerprint: `{v['fingerprint']}`")
        lines.append(f"- Manifest signature: **{'VALID' if v['manifest_signature'] else 'INVALID'}**")
        lines.append(f"- Chain of custody: **{'INTACT' if v['custody_chain'] else 'BROKEN'}**")
        lines.append(f"- Audit log: **{'TAMPER-EVIDENT / INTACT' if v['audit_chain'] else 'BROKEN'}**")
        lines.append("")
        lines.append("## Evidence manifest")
        lines.append("")
        if manifest.items:
            lines.append("| # | File | Size | SHA-256 | Collected |")
            lines.append("|---|------|------|---------|-----------|")
            for i, it in enumerate(sorted(manifest.items, key=lambda x: (x.path, x.sha256)), 1):
                lines.append(
                    f"| {i} | {Path(it.path).name} | {it.size} | `{it.sha256[:16]}…` | {it.collected_at} |"
                )
        else:
            lines.append("_No evidence recorded._")
        lines.append("")
        lines.append("## Observations")
        lines.append("")
        observations = self.observations()
        if observations:
            lines.append("| ID | Current status | Subject | Evidence | Current text | Original text |")
            lines.append("|----|----------------|---------|----------|--------------|---------------|")
            for obs in observations:
                effective = self.effective_observation(obs.observation_id)
                evidence = ", ".join(sha[:16] for sha in obs.evidence) or "-"
                subject = obs.subject or "-"
                current_text = effective.current_text.replace("|", "\\|").replace("\n", " ")
                original_text = obs.text.replace("|", "\\|").replace("\n", " ")
                lines.append(
                    f"| {obs.observation_id} | {effective.current_status} | {subject} | "
                    f"`{evidence}` | {current_text} | {original_text} |"
                )
        else:
            lines.append("_No observations recorded._")
        lines.append("")
        amendments = self.observation_amendments()
        if amendments:
            lines.append("### Observation amendments")
            lines.append("")
            lines.append("| Amendment | Observation | Type | Text | Reason |")
            lines.append("|-----------|-------------|------|------|--------|")
            for amendment in amendments:
                text = amendment.text.replace("|", "\\|").replace("\n", " ")
                reason = (amendment.reason or "-").replace("|", "\\|").replace("\n", " ")
                lines.append(
                    f"| {amendment.amendment_id} | {amendment.observation_id} | "
                    f"{amendment.amendment_type} | {text} | {reason} |"
                )
            lines.append("")
        lines.append("## Timeline (audit log)")
        lines.append("")
        lines.append("| Seq | Time | Actor | Action | Detail |")
        lines.append("|-----|------|-------|--------|--------|")
        for e in self._load_audit():
            detail = ", ".join(f"{k}={v2}" for k, v2 in e.detail.items()
                               if k in ("severity", "file", "sha256", "note", "title"))
            lines.append(f"| {e.seq} | {e.timestamp} | {e.actor} | {e.action} | {detail[:60]} |")
        lines.append("")
        lines.append("## Quality gates")
        lines.append("")
        for g in gates:
            mark = "PASS" if g.passed else "FAIL"
            lines.append(f"- [{mark}] {g.label} — {g.detail}")
        lines.append("")
        if blocking:
            lines.append("> ⚠️ Report generated with UNMET gates: "
                         + ", ".join(g.key for g in blocking))
            lines.append("")

        report_md = "\n".join(lines)
        self.report_path.write_text(report_md, encoding="utf-8")

        self.state["updated_at"] = to_iso(when)
        self._save_state()
        self._append_audit(actor, "report-generated",
                          {"blocking_gates": [g.key for g in blocking]}, when)
        return report_md
