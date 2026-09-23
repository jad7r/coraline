"""Authenticated semantic incident checkpoints. No network or embedded trust keys."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from core.evidence._util import canonical_json, to_iso
from core.evidence.integrity import signing

DOMAIN = "coreline.incident-snapshot.v1"
PREFIX = (DOMAIN + "\0").encode()
ID_RE = re.compile(r"SNP-[0-9a-f]{64}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
SOURCES = {
    "state.json": "state", "manifest.json": "manifest",
    "manifest.sig": "manifest-signature", "signer.json": "manifest-signer",
    "audit.jsonl": "audit", "subjects.json": "subjects",
    "observations.json": "observations", "claims.json": "claims",
    "actions.json": "actions", "decisions.json": "decisions",
}
REQUIRED = {"state.json", "manifest.json", "manifest.sig", "signer.json", "audit.jsonl"}
COLLECTIONS = {
    "subjects.json": (("subjects", "subject_id", "subject"),),
    "observations.json": (("observations", "observation_id", "observation"),
                          ("amendments", "amendment_id", "observation-amendment")),
    "claims.json": (("claims", "claim_id", "claim"), ("amendments", "amendment_id", "claim-amendment")),
    "actions.json": (("actions", "action_id", "action"), ("amendments", "amendment_id", "action-amendment")),
    "decisions.json": (("decisions", "decision_id", "decision"), ("amendments", "amendment_id", "decision-amendment")),
}
PAYLOAD_FIELDS = {
    "domain", "schema_version", "snapshot_id", "incident_id", "sequence",
    "created_at", "created_by", "previous_snapshot_id", "previous_snapshot_digest",
    "audit_head_hash", "audit_length", "incident_state_digest", "record_count",
    "records", "signing_key_id", "signature_algorithm", "final",
}
MAX_BYTES = 64 * 1024 * 1024


class SnapshotError(Exception):
    """Safe, value-free diagnostic for a failed checkpoint operation."""


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value):
    # canonical_json is the shared core serialization; disallow non-JSON numbers.
    json.dumps(value, allow_nan=False)
    return canonical_json(value).encode("utf-8")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(_):
    raise SnapshotError("non-finite JSON number")


def parse_json(data):
    return json.loads(data, object_pairs_hook=_pairs, parse_constant=_bad_constant)


def _no_symlinks(path):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise SnapshotError("symlinks are not permitted in checkpoint paths")


def _read(path):
    _no_symlinks(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise SnapshotError("checkpoint source must be a bounded regular file")
        data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise SnapshotError("checkpoint source too large")
        return data


def _publish(path, data, mode=0o600):
    """fsync + atomic no-overwrite publication; a failed write cannot replace history."""
    _no_symlinks(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".snapshot-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # Atomic and fails if destination already exists.
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def public_key_path(home):
    return Path(os.environ.get("CORELINE_SNAPSHOT_VERIFY_KEY") or Path(home) / "trust" / "snapshot.verify.json")


def load_public_key(path, *, incident_dir=None):
    try:
        if incident_dir is not None and Path(path).resolve().is_relative_to(Path(incident_dir).resolve()):
            raise ValueError()
        info = parse_json(_read(Path(path)))
        if info.get("algorithm", "ed25519") != "ed25519":
            raise ValueError()
        base64.b64decode(info["verify_key"], validate=True)
        key = signing.decode_verify_key(info["verify_key"])
        if info.get("fingerprint", signing.key_fingerprint(key)) != signing.key_fingerprint(key):
            raise ValueError()
        return key
    except Exception:
        raise SnapshotError("snapshot public verification key unavailable or invalid") from None


def load_private_key(path, home):
    try:
        path = Path(path)
        if path.resolve().is_relative_to(Path(home).resolve()):
            raise SnapshotError("snapshot private key must be outside the incident store")
        return signing.decode_signing_key(base64.b64decode(_read(path).strip(), validate=True))
    except SnapshotError:
        raise
    except Exception:
        raise SnapshotError("snapshot signing key unavailable or invalid") from None


def generate_key_files(home, private_path, public_path):
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.resolve().is_relative_to(Path(home).resolve()):
        raise SnapshotError("snapshot private key must be outside the incident store")
    if private_path.resolve() == public_path.resolve() or private_path.exists() or public_path.exists():
        raise SnapshotError("key paths must be distinct and unused")
    if (public_path.resolve().is_relative_to(Path(home).resolve()) and
            not public_path.resolve().is_relative_to((Path(home) / "trust").resolve())):
        raise SnapshotError("public pin inside the store must be under trust, outside incidents")
    key, public = signing.generate_signing_keypair()
    _publish(private_path, base64.b64encode(signing.encode_signing_key(key)))
    _publish(public_path, canonical_bytes({"algorithm": "ed25519", "verify_key": signing.encode_verify_key(public),
                                         "fingerprint": signing.key_fingerprint(public)}), 0o644)
    return signing.key_fingerprint(public)


def _entry(kind, identifier, source, value, raw=False):
    data = value if raw else canonical_bytes(value)
    return {"type": kind, "id": str(identifier), "source": source, "size": len(data), "sha256": _hash(data)}


def state_digest(incident_id, records):
    records = sorted(records, key=lambda r: (r["source"], r["type"], r["id"]))
    return _hash(canonical_bytes({"schema_version": 1, "incident_id": incident_id, "records": records}))


def inventory(workspace, *, allow_missing=False):
    """Canonical metadata inventory. Never reads evidence blobs or secret keys."""
    records, audit = [], []
    for source, kind in sorted(SOURCES.items()):
        path = workspace.dir / source
        if not path.exists() and not path.is_symlink():
            if source in REQUIRED and not allow_missing:
                raise SnapshotError("required authoritative source missing")
            continue
        data = _read(path)
        if source == "manifest.sig":
            records.append(_entry(kind, kind, source, base64.b64decode(data.strip(), validate=True), raw=True))
            continue
        if source == "audit.jsonl":
            audit = [parse_json(line) for line in data.splitlines() if line.strip()]
            value = audit
            for index, record in enumerate(audit, 1):
                records.append(_entry("audit-entry", index, source, record))
        else:
            value = parse_json(data)
            if not isinstance(value, dict):
                raise SnapshotError("authoritative source must be an object")
            if source == "state.json" or source == "manifest.json" or source in COLLECTIONS:
                if value.get("incident_id") != workspace.incident_id:
                    raise SnapshotError("authoritative incident identity mismatch")
            for collection, id_key, record_type in COLLECTIONS.get(source, ()):
                items = value.get(collection, [])
                identifiers = [item[id_key] for item in items]
                if len(set(identifiers)) != len(identifiers):
                    raise SnapshotError("duplicate authoritative record ID")
                if collection in value:
                    value[collection] = sorted(items, key=lambda item: item[id_key])
                for item in items:
                    records.append(_entry(record_type, item[id_key], source, item))
            if source == "manifest.json":
                items = sorted(value.get("items", []), key=canonical_bytes)
                if "items" in value:
                    value["items"] = items
                for index, item in enumerate(items):
                    records.append(_entry("evidence", f"{item['sha256']}:{index}", source, item))
                for index, event in enumerate(value.get("custody", []), 1):
                    records.append(_entry("custody-event", index, source, event))
        records.append(_entry(kind, kind, source, value))
    if not audit and not allow_missing:
        raise SnapshotError("audit must not be empty")
    records.sort(key=lambda r: (r["source"], r["type"], r["id"]))
    return {"records": records, "record_count": len(records),
            "incident_state_digest": state_digest(workspace.incident_id, records),
            "audit_head_hash": audit[-1]["entry_hash"] if audit else None, "audit_length": len(audit)}


def snapshot_id(payload):
    return "SNP-" + _hash(canonical_bytes({k: v for k, v in payload.items() if k != "snapshot_id"}))


def snapshot_digest(envelope):
    return _hash(canonical_bytes(envelope))


def verify_document(envelope, verify_key, *, incident_id=None, expected_id=None):
    """Portable verification against a caller-supplied pin; never consult local state."""
    result = {"structure_valid": False, "signer_trusted": False, "signature_valid": False, "errors": []}
    try:
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError()
        p = envelope["payload"]
        if set(p) != PAYLOAD_FIELDS or p["domain"] != DOMAIN or type(p["schema_version"]) is not int or p["schema_version"] != 1:
            raise ValueError()
        if p["signature_algorithm"] != "ed25519" or type(p["final"]) is not bool:
            raise ValueError()
        for field in ("sequence", "audit_length", "record_count"):
            if type(p[field]) is not int or p[field] < 1:
                raise ValueError()
        for field in ("incident_id", "created_by", "signing_key_id"):
            if not isinstance(p[field], str) or not p[field].strip():
                raise ValueError()
        if incident_id is not None and p["incident_id"] != incident_id:
            raise ValueError()
        if expected_id is not None and p["snapshot_id"] != expected_id:
            raise ValueError()
        if not ID_RE.fullmatch(p["snapshot_id"]) or p["snapshot_id"] != snapshot_id(p):
            raise ValueError()
        if not p["created_at"].endswith("Z") or to_iso(datetime.fromisoformat(p["created_at"].replace("Z", "+00:00"))) != p["created_at"]:
            raise ValueError()
        for field in ("audit_head_hash", "incident_state_digest"):
            if not HASH_RE.fullmatch(p[field]):
                raise ValueError()
        if p["sequence"] == 1:
            if p["previous_snapshot_id"] is not None or p["previous_snapshot_digest"] is not None:
                raise ValueError()
        elif not ID_RE.fullmatch(p["previous_snapshot_id"]) or not HASH_RE.fullmatch(p["previous_snapshot_digest"]):
            raise ValueError()
        records = p["records"]
        if not isinstance(records, list) or len(records) != p["record_count"]:
            raise ValueError()
        keys = []
        for r in records:
            if set(r) != {"type", "id", "source", "size", "sha256"} or r["source"] not in SOURCES:
                raise ValueError()
            if any(not isinstance(r[k], str) or not r[k] for k in ("type", "id")):
                raise ValueError()
            if type(r["size"]) is not int or r["size"] < 0 or not HASH_RE.fullmatch(r["sha256"]):
                raise ValueError()
            keys.append((r["source"], r["type"], r["id"]))
        if keys != sorted(set(keys)) or p["incident_state_digest"] != state_digest(p["incident_id"], records):
            raise ValueError()
        if not REQUIRED.issubset({r["source"] for r in records}):
            raise ValueError()
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(signature) != signing.SIGNATURE_BYTES:
            raise ValueError()
        result["structure_valid"] = True
        result["signer_trusted"] = verify_key is not None and p["signing_key_id"] == signing.key_fingerprint(verify_key)
        result["signature_valid"] = result["signer_trusted"] and signing.verify(PREFIX + canonical_bytes(p), signature, verify_key)
        if not result["signer_trusted"]:
            result["errors"].append("UNKNOWN SIGNER")
        elif not result["signature_valid"]:
            result["errors"].append("SIGNATURE INVALID")
    except Exception:
        result["errors"].append("INVALID SNAPSHOT STRUCTURE OR IDENTITY")
    result["valid"] = all(result[k] for k in ("structure_valid", "signer_trusted", "signature_valid"))
    return result


class SnapshotStore:
    def __init__(self, workspace, verify_key=None):
        self.ws = workspace
        self.directory = workspace.dir / "snapshots"
        self.key = verify_key
        if self.key is None:
            try:
                pin = public_key_path(workspace.home)
                self.key = load_public_key(pin, incident_dir=workspace.dir)
            except SnapshotError:
                pass
        self.trust = None
        try:
            from .trust_registry import TrustRegistryStore
            self.trust = TrustRegistryStore.discover(workspace.home, incident_dir=workspace.dir)
        except Exception:
            # A present but malformed registry is handled fail-closed by _check_document/create.
            from .trust_registry import root_path
            if root_path(workspace.home).exists():
                self.trust = False

    def _check_document(self, document, *, expected_id=None):
        if self.trust is False:
            return {"valid": False, "structure_valid": False, "signer_trusted": False,
                    "signature_valid": False, "signer_status": "REGISTRY_INVALID",
                    "errors": ["TRUST REGISTRY INVALID"]}
        if self.trust:
            key_id = document.get("payload", {}).get("signing_key_id")
            qualified = self.trust.classify_key(key_id, "SNAPSHOT_SIGNER", "default")
            check = verify_document(document, qualified["key"], incident_id=self.ws.incident_id,
                                    expected_id=expected_id)
            check["signer_status"] = qualified["classification"]
            if not qualified["trusted"]:
                check["valid"] = False
                check["errors"].append(qualified["classification"])
            return check
        check = verify_document(document, self.key, incident_id=self.ws.incident_id,
                                expected_id=expected_id)
        check["signer_status"] = "LEGACY_PIN" if check["signer_trusted"] else "UNKNOWN_KEY"
        return check

    def _paths(self):
        _no_symlinks(self.directory)
        if not self.directory.exists():
            return []
        paths = []
        for path in self.directory.iterdir():
            if path.name.startswith(".snapshot-") and path.name.endswith(".tmp"):
                continue
            if path.suffix != ".json" or not ID_RE.fullmatch(path.stem):
                raise SnapshotError("unexpected snapshot directory entry")
            paths.append(path)
        return sorted(paths)

    def read(self, identifier):
        if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier):
            raise SnapshotError("invalid snapshot ID")
        try:
            return parse_json(_read(self.directory / f"{identifier}.json"))
        except Exception:
            raise SnapshotError("snapshot unreadable or malformed") from None

    def verify_snapshot(self, identifier):
        try:
            return self._check_document(self.read(identifier), expected_id=identifier)
        except Exception:
            return {"valid": False, "structure_valid": False, "signer_trusted": False,
                    "signature_valid": False, "errors": ["SNAPSHOT MISSING OR MALFORMED"]}

    def verify_chain(self, expected_tip=None):
        result = {"valid": False, "status": "CHAIN_BROKEN", "count": 0, "latest": None, "errors": []}
        try:
            if expected_tip is not None and not (ID_RE.fullmatch(expected_tip) or HASH_RE.fullmatch(expected_tip)):
                raise SnapshotError("invalid expected checkpoint tip")
            documents = []
            for path in self._paths():
                document = self.read(path.stem)
                check = self._check_document(document, expected_id=path.stem)
                if not check["valid"]:
                    result["errors"].extend(check["errors"])
                    return result
                documents.append(document)
            documents.sort(key=lambda d: d["payload"]["sequence"])
            previous = None
            for index, document in enumerate(documents, 1):
                p = document["payload"]
                if p["sequence"] != index:
                    raise SnapshotError("missing or duplicate snapshot sequence")
                if previous and (previous["payload"]["final"] or
                                 p["previous_snapshot_id"] != previous["payload"]["snapshot_id"] or
                                 p["previous_snapshot_digest"] != snapshot_digest(previous)):
                    raise SnapshotError("snapshot predecessor mismatch")
                previous = document
            if expected_tip is not None and (previous is None or expected_tip not in
                                 (previous["payload"]["snapshot_id"], snapshot_digest(previous))):
                raise SnapshotError("expected checkpoint tip absent")
            result.update(valid=True, status="VALID" if previous else "NOT_PRESENT", count=len(documents), latest=previous)
        except Exception:
            result["errors"].append("CHAIN BROKEN OR UNREADABLE")
        return result

    def compare_current(self, identifier):
        try:
            document = self.read(identifier)
            check = self._check_document(document, expected_id=identifier)
        except Exception:
            document = None
            check = {"valid": False, "structure_valid": False, "signer_trusted": False,
                     "signature_valid": False, "errors": ["SNAPSHOT MISSING OR MALFORMED"]}
        result = {"snapshot": check, "records_match": False,
                  "current_state_matches": False, "missing": [], "modified": [], "added": [], "errors": []}
        if not result["snapshot"]["valid"]:
            return result
        try:
            p = document["payload"]
            current = inventory(self.ws, allow_missing=True)
            key = lambda r: (r["source"], r["type"], r["id"])
            old = {key(r): r for r in p["records"]}
            new = {key(r): r for r in current["records"]}
            result["missing"] = [list(k) for k in sorted(old.keys() - new.keys())]
            result["added"] = [list(k) for k in sorted(new.keys() - old.keys())]
            result["modified"] = [list(k) for k in sorted(old.keys() & new.keys()) if old[k] != new[k]]
            result["records_match"] = not result["missing"] and not result["modified"]
            result["current_state_matches"] = p["incident_state_digest"] == current["incident_state_digest"]
        except Exception:
            result["errors"].append("AUTHORITATIVE RECORD MISSING, UNREADABLE OR MALFORMED")
        return result

    def health(self):
        chain = self.verify_chain()
        result = {"valid": chain["valid"], "status": chain["status"], "chain_valid": chain["valid"],
                  "latest_id": None, "signature_valid": None, "current_state_matches": None}
        latest = chain["latest"]
        if latest:
            p = latest["payload"]
            latest_check = self._check_document(latest, expected_id=p["snapshot_id"])
            comparison = self.compare_current(p["snapshot_id"])
            result.update(latest_id=p["snapshot_id"], created_at=p["created_at"],
                          state_digest=p["incident_state_digest"], signing_key_id=p["signing_key_id"],
                          signature_valid=latest_check["signature_valid"],
                          signer_status=latest_check.get("signer_status"), final=p["final"],
                          current_state_matches=comparison["current_state_matches"])
            if not comparison["current_state_matches"]:
                result["status"] = "CURRENT_STATE_DIFFERS"
            try:
                audit = self.ws._load_audit()
                prefix_ok = len(audit) >= p["audit_length"] and audit[p["audit_length"] - 1].entry_hash() == p["audit_head_hash"]
            except Exception:
                prefix_ok = False
            if comparison["errors"] or not prefix_ok or (p["final"] and not comparison["current_state_matches"]):
                result["valid"] = False
                result["status"] = "INVALID"
            if self.ws.state.get("snapshot_final_required") and not p["final"]:
                result.update(valid=False, status="FINAL_SNAPSHOT_MISSING")
        elif self.ws.state.get("snapshot_final_required"):
            result.update(valid=False, status="FINAL_SNAPSHOT_MISSING")
        return result

    def create(self, signing_key, actor, when=None):
        try:
            _no_symlinks(self.ws.dir)
            _no_symlinks(self.ws._lock_path)
            # Check all checkpoint paths before the legacy verifier reads them.
            inventory(self.ws)
            with self.ws._mutation_lock():
                from .workspace import IncidentWorkspace
                fresh = IncidentWorkspace.load(self.ws.home, self.ws.incident_id)
                self.ws.state = fresh.state
                if not actor or not actor.strip():
                    raise SnapshotError("checkpoint actor required")
                signing_verify_key = self.key
                if self.trust is False:
                    raise SnapshotError("signed trust registry invalid")
                if self.trust:
                    try:
                        self.trust.authorize(signing_key, "SNAPSHOT_SIGNER", "default")
                        signing_verify_key = signing_key.verify_key
                    except Exception:
                        raise SnapshotError("snapshot signing key is not active in signed registry") from None
                elif (self.key is None or signing.key_fingerprint(signing_key.verify_key) !=
                      signing.key_fingerprint(self.key)):
                    raise SnapshotError("snapshot signing key does not match public pin")
                chain = self.verify_chain()
                if not chain["valid"]:
                    raise SnapshotError("existing snapshot chain invalid")
                previous = chain["latest"]
                if previous and previous["payload"]["final"]:
                    raise SnapshotError("final checkpoint already exists")
                if previous:
                    audit = self.ws._load_audit()
                    count = previous["payload"]["audit_length"]
                    if len(audit) < count or audit[count - 1].entry_hash() != previous["payload"]["audit_head_hash"]:
                        raise SnapshotError("current audit contradicts the latest checkpoint")
                if not self.ws.verify(include_snapshots=False, include_anchors=False)["ok"]:
                    raise SnapshotError("incident integrity verification failed")
                captured = inventory(self.ws)
                payload = {"domain": DOMAIN, "schema_version": 1, "incident_id": self.ws.incident_id,
                           "sequence": chain["count"] + 1, "created_at": to_iso(when or datetime.now(timezone.utc)),
                           "created_by": actor, "previous_snapshot_id": previous["payload"]["snapshot_id"] if previous else None,
                           "previous_snapshot_digest": snapshot_digest(previous) if previous else None,
                           **captured, "signing_key_id": signing.key_fingerprint(signing_verify_key),
                           "signature_algorithm": "ed25519", "final": self.ws.is_sealed}
                payload["snapshot_id"] = snapshot_id(payload)
                envelope = {"payload": payload, "signature": base64.b64encode(signing.sign(PREFIX + canonical_bytes(payload), signing_key)).decode("ascii")}
                if not verify_document(envelope, signing_verify_key, incident_id=self.ws.incident_id)["valid"]:
                    raise SnapshotError("new snapshot verification failed")
                if inventory(self.ws) != captured:
                    raise SnapshotError("incident changed during checkpoint creation")
                encoded = canonical_bytes(envelope)
                if len(encoded) > MAX_BYTES:
                    raise SnapshotError("snapshot exceeds supported size")
                _publish(self.directory / f"{payload['snapshot_id']}.json", encoded)
                return envelope
        except SnapshotError:
            raise
        except Exception:
            raise SnapshotError("snapshot creation failed; no history was rewritten") from None


def report_section(health):
    lines = ["## Integrity checkpoint", "", f"- Snapshot status: {health['status']}"]
    for field, label in (("latest_id", "Snapshot ID"), ("created_at", "Checkpoint time"),
                         ("state_digest", "State digest"), ("signing_key_id", "Signer key"),
                         ("signer_status", "Signer trust status"),
                         ("signature_valid", "Signature valid"), ("chain_valid", "Chain valid"),
                         ("final", "Final sealed checkpoint"),
                         ("current_state_matches", "Current state matches")):
        lines.append(f"- {label}: {health.get(field)}")
    lines.extend(["", "Checkpoint comparison describes the state when this section was rendered.", ""])
    return "\n".join(lines)
