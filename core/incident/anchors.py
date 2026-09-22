"""Independent acknowledgements for authenticated incident snapshots.

Anchors authenticate checkpoint references only.  They never receive or mutate
incident content and never supply trust keys to their verifier.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from core.evidence._util import to_iso
from core.evidence.integrity import signing
from .snapshots import (
    HASH_RE, ID_RE as SNAPSHOT_ID_RE, MAX_BYTES, SnapshotError, SnapshotStore,
    _no_symlinks, _publish, _read, canonical_bytes, parse_json, snapshot_digest,
)

DOMAIN = "coreline.snapshot-anchor-receipt.v1"
PREFIX = (DOMAIN + "\0").encode()
RECEIPT_ID_RE = re.compile(r"ANC-[0-9a-f]{64}\Z")
ANCHOR_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
POLICIES = {"OPTIONAL", "REQUIRED", "REQUIRED_FOR_SEAL"}
PROVIDER_TYPES = {"filesystem-v1", "gcs-v1"}
REQUEST_FIELDS = {
    "schema_version", "incident_id", "snapshot_id", "snapshot_digest",
    "state_digest", "snapshot_signer_key_id", "snapshot_sequence",
    "previous_snapshot_id", "previous_snapshot_digest",
}
PAYLOAD_FIELDS = REQUEST_FIELDS | {
    "domain", "receipt_schema_version", "anchor_id", "anchor_type", "receipt_id",
    "anchor_sequence", "acknowledged_at", "anchor_key_id", "authentication_algorithm",
    "previous_receipt_id", "previous_receipt_digest",
}


class AnchorError(Exception):
    """Value-free anchor failure safe for operator output."""


class AnchorUnavailable(AnchorError):
    """The provider could not be queried; this is distinct from invalid data."""


class SnapshotAnchor(Protocol):
    """Minimal provider boundary; implementations retain and authenticate receipts."""
    def anchor(self, request, acknowledged_at=None): ...
    def get_expected_tip(self, incident_id): ...
    def verify_ledger(self, incident_id): ...

    def capabilities(self): ...


def anchor_capabilities(anchor_type):
    if anchor_type not in PROVIDER_TYPES:
        raise AnchorError("unsupported trusted anchor provider")
    return {"provider": anchor_type, "conditional_create": True,
            "durable_read": True, "durable_list": True,
            "retention_managed_externally": True, "retention_verified": False,
            "independently_trusted_time": False}


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def receipt_id(payload):
    return "ANC-" + _hash(canonical_bytes({k: v for k, v in payload.items() if k != "receipt_id"}))


def receipt_digest(receipt):
    return _hash(canonical_bytes(receipt))


def request_from_snapshot(document):
    p = document["payload"]
    return {
        "schema_version": 1,
        "incident_id": p["incident_id"],
        "snapshot_id": p["snapshot_id"],
        "snapshot_digest": snapshot_digest(document),
        "state_digest": p["incident_state_digest"],
        "snapshot_signer_key_id": p["signing_key_id"],
        "snapshot_sequence": p["sequence"],
        "previous_snapshot_id": p["previous_snapshot_id"],
        "previous_snapshot_digest": p["previous_snapshot_digest"],
    }


def _validate_request(request):
    if not isinstance(request, dict) or set(request) != REQUEST_FIELDS:
        raise AnchorError("invalid anchor request")
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise AnchorError("invalid anchor request")
    if not isinstance(request["incident_id"], str) or not request["incident_id"]:
        raise AnchorError("invalid anchor request")
    if not SNAPSHOT_ID_RE.fullmatch(request["snapshot_id"]):
        raise AnchorError("invalid anchor request")
    if type(request["snapshot_sequence"]) is not int or request["snapshot_sequence"] < 1:
        raise AnchorError("invalid anchor request")
    for field in ("snapshot_digest", "state_digest"):
        if not isinstance(request[field], str) or not HASH_RE.fullmatch(request[field]):
            raise AnchorError("invalid anchor request")
    if not isinstance(request["snapshot_signer_key_id"], str) or not request["snapshot_signer_key_id"]:
        raise AnchorError("invalid anchor request")
    if request["snapshot_sequence"] == 1:
        if request["previous_snapshot_id"] is not None or request["previous_snapshot_digest"] is not None:
            raise AnchorError("invalid anchor request")
    elif (not isinstance(request["previous_snapshot_id"], str) or
          not SNAPSHOT_ID_RE.fullmatch(request["previous_snapshot_id"]) or
          not isinstance(request["previous_snapshot_digest"], str) or
          not HASH_RE.fullmatch(request["previous_snapshot_digest"])):
        raise AnchorError("invalid anchor request")
    canonical_bytes(request)


def verify_receipt(receipt, verify_key, *, anchor_id=None, incident_id=None,
                   anchor_type="filesystem-v1"):
    result = {"receipt_structurally_valid": False, "anchor_trusted": False,
              "receipt_authentic": False, "errors": []}
    try:
        if not isinstance(receipt, dict) or set(receipt) != {"payload", "signature"}:
            raise ValueError()
        p = receipt["payload"]
        if not isinstance(p, dict) or set(p) != PAYLOAD_FIELDS:
            raise ValueError()
        request = {field: p[field] for field in REQUEST_FIELDS}
        _validate_request(request)
        if (p["domain"] != DOMAIN or p["receipt_schema_version"] != 1 or
                p["anchor_type"] != anchor_type or p["authentication_algorithm"] != "ed25519"):
            raise ValueError()
        if not ANCHOR_ID_RE.fullmatch(p["anchor_id"]):
            raise ValueError()
        if anchor_id is not None and p["anchor_id"] != anchor_id:
            raise ValueError()
        if incident_id is not None and p["incident_id"] != incident_id:
            raise ValueError()
        if type(p["anchor_sequence"]) is not int or p["anchor_sequence"] < 1:
            raise ValueError()
        if (not isinstance(p["acknowledged_at"], str) or not p["acknowledged_at"].endswith("Z") or
                to_iso(datetime.fromisoformat(p["acknowledged_at"].replace("Z", "+00:00"))) != p["acknowledged_at"]):
            raise ValueError()
        if not RECEIPT_ID_RE.fullmatch(p["receipt_id"]) or p["receipt_id"] != receipt_id(p):
            raise ValueError()
        if p["anchor_sequence"] == 1:
            if p["previous_receipt_id"] is not None or p["previous_receipt_digest"] is not None:
                raise ValueError()
        elif (not RECEIPT_ID_RE.fullmatch(p["previous_receipt_id"]) or
              not HASH_RE.fullmatch(p["previous_receipt_digest"])):
            raise ValueError()
        signature = base64.b64decode(receipt["signature"], validate=True)
        if len(signature) != signing.SIGNATURE_BYTES:
            raise ValueError()
        result["receipt_structurally_valid"] = True
        result["anchor_trusted"] = (verify_key is not None and
                                    p["anchor_key_id"] == signing.key_fingerprint(verify_key))
        result["receipt_authentic"] = result["anchor_trusted"] and signing.verify(
            PREFIX + canonical_bytes(p), signature, verify_key)
        if not result["anchor_trusted"]:
            result["errors"].append("UNKNOWN ANCHOR")
        elif not result["receipt_authentic"]:
            result["errors"].append("RECEIPT SIGNATURE INVALID")
    except Exception:
        result["errors"].append("INVALID RECEIPT STRUCTURE OR IDENTITY")
    result["valid"] = all(result[k] for k in
                          ("receipt_structurally_valid", "anchor_trusted", "receipt_authentic"))
    return result


def registry_path(home):
    return Path(os.environ.get("CORELINE_ANCHOR_REGISTRY") or Path(home) / "trust" / "anchors.json")


def load_registry(path, *, incident_dir=None):
    try:
        path = Path(path)
        if incident_dir is not None and path.resolve().is_relative_to(Path(incident_dir).resolve()):
            raise ValueError()
        data = parse_json(_read(path))
        if set(data) != {"schema_version", "default_anchor", "anchors"} or data["schema_version"] != 1:
            raise ValueError()
        anchors = {}
        for item in data["anchors"]:
            common = {"anchor_id", "anchor_type", "verify_key", "fingerprint", "policy", "enabled"}
            provider_fields = ({"root"} if item.get("anchor_type") == "filesystem-v1"
                               else {"bucket", "prefix"} if item.get("anchor_type") == "gcs-v1"
                               else None)
            if provider_fields is None or set(item) != common | provider_fields:
                raise ValueError()
            if (not ANCHOR_ID_RE.fullmatch(item["anchor_id"]) or
                    item["policy"] not in POLICIES or type(item["enabled"]) is not bool or
                    item["anchor_id"] in anchors):
                raise ValueError()
            key = signing.decode_verify_key(item["verify_key"])
            if (item["anchor_type"] == "filesystem-v1" and incident_dir is not None and
                    Path(item["root"]).resolve().is_relative_to(Path(incident_dir).resolve())):
                raise ValueError()
            if item["anchor_type"] == "gcs-v1":
                from .gcs_anchor import validate_gcs_location
                validate_gcs_location(item["bucket"], item["prefix"])
            if item["fingerprint"] != signing.key_fingerprint(key):
                raise ValueError()
            anchors[item["anchor_id"]] = {**item, "key": key}
        if data["default_anchor"] not in anchors or not anchors[data["default_anchor"]]["enabled"]:
            raise ValueError()
        return {"default_anchor": data["default_anchor"], "anchors": anchors}
    except Exception:
        raise AnchorError("trusted anchor registry unavailable or invalid") from None


def write_registry(path, anchor_id, root, verify_key, policy="OPTIONAL"):
    if not ANCHOR_ID_RE.fullmatch(anchor_id) or policy not in POLICIES:
        raise AnchorError("invalid trusted anchor configuration")
    payload = {"schema_version": 1, "default_anchor": anchor_id, "anchors": [{
        "anchor_id": anchor_id, "anchor_type": "filesystem-v1", "root": str(Path(root).resolve()),
        "verify_key": signing.encode_verify_key(verify_key),
        "fingerprint": signing.key_fingerprint(verify_key), "policy": policy, "enabled": True,
    }]}
    try:
        _publish(Path(path), canonical_bytes(payload), 0o600)
    except Exception:
        raise AnchorError("trusted anchor registry could not be created") from None


def write_gcs_registry(path, anchor_id, bucket, prefix, verify_key, policy="OPTIONAL"):
    """Create a pinned GCS anchor configuration without provider credentials."""
    from .gcs_anchor import validate_gcs_location
    if not ANCHOR_ID_RE.fullmatch(anchor_id) or policy not in POLICIES:
        raise AnchorError("invalid trusted anchor configuration")
    validate_gcs_location(bucket, prefix)
    payload = {"schema_version": 1, "default_anchor": anchor_id, "anchors": [{
        "anchor_id": anchor_id, "anchor_type": "gcs-v1", "bucket": bucket,
        "prefix": prefix, "verify_key": signing.encode_verify_key(verify_key),
        "fingerprint": signing.key_fingerprint(verify_key), "policy": policy, "enabled": True,
    }]}
    try:
        _publish(Path(path), canonical_bytes(payload), 0o600)
    except Exception:
        raise AnchorError("trusted anchor registry could not be created") from None


class FilesystemAnchor:
    """Append-only signed receipt ledger in a separately configured directory."""
    def __init__(self, root, anchor_id, verify_key, signing_key=None):
        if not ANCHOR_ID_RE.fullmatch(anchor_id):
            raise AnchorError("invalid anchor identity")
        self.root, self.anchor_id = Path(root), anchor_id
        self.verify_key, self.signing_key = verify_key, signing_key

    def capabilities(self):
        return anchor_capabilities("filesystem-v1")

    def _incident_dir(self, incident_id):
        return self.root / "ledger" / hashlib.sha256(incident_id.encode()).hexdigest()

    @contextmanager
    def _lock(self, incident_id):
        _no_symlinks(self.root)
        locks = self.root / "locks"
        locks.mkdir(parents=True, exist_ok=True)
        path = locks / (hashlib.sha256(incident_id.encode()).hexdigest() + ".lock")
        _no_symlinks(path)
        with path.open("a+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _paths(self, incident_id):
        directory = self._incident_dir(incident_id)
        _no_symlinks(directory)
        if not directory.exists():
            return []
        paths = []
        for path in directory.iterdir():
            if path.name.startswith(".snapshot-") and path.name.endswith(".tmp"):
                continue
            if path.suffix != ".json" or not RECEIPT_ID_RE.fullmatch(path.stem):
                raise AnchorError("unexpected anchor ledger entry")
            paths.append(path)
        return sorted(paths)

    def read(self, receipt_identifier, incident_id):
        if not RECEIPT_ID_RE.fullmatch(receipt_identifier):
            raise AnchorError("invalid receipt ID")
        try:
            data = _read(self._incident_dir(incident_id) / f"{receipt_identifier}.json")
        except OSError:
            raise AnchorUnavailable("anchor provider unavailable") from None
        try:
            return parse_json(data)
        except Exception:
            raise AnchorError("receipt unreadable or malformed") from None

    def verify_ledger(self, incident_id):
        result = {"valid": False, "count": 0, "latest": None, "errors": []}
        try:
            receipts = []
            for path in self._paths(incident_id):
                item = self.read(path.stem, incident_id)
                check = verify_receipt(item, self.verify_key, anchor_id=self.anchor_id,
                                       incident_id=incident_id, anchor_type="filesystem-v1")
                if not check["valid"] or item["payload"]["receipt_id"] != path.stem:
                    raise AnchorError("invalid receipt")
                receipts.append(item)
            receipts.sort(key=lambda item: item["payload"]["anchor_sequence"])
            previous = None
            for index, item in enumerate(receipts, 1):
                p = item["payload"]
                if p["anchor_sequence"] != index or p["snapshot_sequence"] != index:
                    raise AnchorError("non-monotonic anchor ledger")
                if previous and (p["previous_receipt_id"] != previous["payload"]["receipt_id"] or
                                 p["previous_receipt_digest"] != receipt_digest(previous) or
                                 p["previous_snapshot_id"] != previous["payload"]["snapshot_id"] or
                                 p["previous_snapshot_digest"] != previous["payload"]["snapshot_digest"]):
                    raise AnchorError("anchor ledger linkage mismatch")
                previous = item
            result.update(valid=True, count=len(receipts), latest=previous)
        except AnchorUnavailable:
            result["unavailable"] = True
            result["errors"].append("ANCHOR UNAVAILABLE")
        except Exception:
            result["unavailable"] = False
            result["errors"].append("ANCHOR LEDGER BROKEN OR UNAVAILABLE")
        return result

    def get_expected_tip(self, incident_id):
        ledger = self.verify_ledger(incident_id)
        if not ledger["valid"]:
            if ledger.get("unavailable"):
                raise AnchorUnavailable("anchor expected tip unavailable")
            raise AnchorError("anchor expected tip unavailable or invalid")
        return ledger["latest"]

    def anchor(self, request, acknowledged_at=None):
        _validate_request(request)
        if self.signing_key is None or signing.key_fingerprint(self.signing_key.verify_key) != signing.key_fingerprint(self.verify_key):
            raise AnchorError("anchor signing authority unavailable or untrusted")
        try:
            with self._lock(request["incident_id"]):
                ledger = self.verify_ledger(request["incident_id"])
                if not ledger["valid"]:
                    raise AnchorError("existing anchor ledger invalid")
                previous = ledger["latest"]
                if previous and request["snapshot_id"] == previous["payload"]["snapshot_id"]:
                    if all(previous["payload"][field] == request[field] for field in REQUEST_FIELDS):
                        return previous
                    raise AnchorError("conflicting duplicate anchor request")
                expected = ledger["count"] + 1
                if request["snapshot_sequence"] != expected:
                    raise AnchorError("snapshots must be anchored sequentially")
                if previous and (request["previous_snapshot_id"] != previous["payload"]["snapshot_id"] or
                                 request["previous_snapshot_digest"] != previous["payload"]["snapshot_digest"]):
                    raise AnchorError("anchor request does not descend from expected tip")
                payload = {**request, "domain": DOMAIN, "receipt_schema_version": 1,
                           "anchor_id": self.anchor_id, "anchor_type": "filesystem-v1",
                           "anchor_sequence": expected,
                           "acknowledged_at": to_iso(acknowledged_at or datetime.now(timezone.utc)),
                           "anchor_key_id": signing.key_fingerprint(self.verify_key),
                           "authentication_algorithm": "ed25519",
                           "previous_receipt_id": previous["payload"]["receipt_id"] if previous else None,
                           "previous_receipt_digest": receipt_digest(previous) if previous else None}
                payload["receipt_id"] = receipt_id(payload)
                receipt = {"payload": payload, "signature": base64.b64encode(
                    signing.sign(PREFIX + canonical_bytes(payload), self.signing_key)).decode("ascii")}
                if not verify_receipt(receipt, self.verify_key, anchor_id=self.anchor_id,
                                      incident_id=request["incident_id"],
                                      anchor_type="filesystem-v1")["valid"]:
                    raise AnchorError("new anchor receipt verification failed")
                encoded = canonical_bytes(receipt)
                if len(encoded) > MAX_BYTES:
                    raise AnchorError("anchor receipt exceeds supported size")
                _publish(self._incident_dir(request["incident_id"]) / f"{payload['receipt_id']}.json", encoded)
                return receipt
        except AnchorError:
            raise
        except Exception:
            raise AnchorError("anchor operation failed without modifying incident state") from None


class AnchorManager:
    """Workspace adapter: cache receipts and derive policy from explicit trust config."""
    def __init__(self, workspace, config=None, snapshot_verify_key=None, online=True):
        self.ws, self.snapshot_key, self.online = workspace, snapshot_verify_key, online
        self.config = config
        self.config_error = False
        if self.config is None:
            try:
                self.config = load_registry(registry_path(workspace.home), incident_dir=workspace.dir)
            except AnchorError:
                self.config_error = registry_path(workspace.home).exists() or (workspace.dir / "anchors").exists()
                self.config = None

    @property
    def entry(self):
        return self.config["anchors"][self.config["default_anchor"]] if self.config else None

    @property
    def cache_dir(self):
        anchor_id = self.entry["anchor_id"] if self.entry else "unknown"
        return self.ws.dir / "anchors" / anchor_id

    def provider(self, signing_key=None):
        if not self.entry:
            raise AnchorError("trusted anchor registry unavailable")
        if self.entry["anchor_type"] == "filesystem-v1":
            return FilesystemAnchor(self.entry["root"], self.entry["anchor_id"],
                                    self.entry["key"], signing_key)
        if self.entry["anchor_type"] == "gcs-v1":
            from .gcs_anchor import GCSAnchor
            return GCSAnchor.keyless(self.entry["bucket"], self.entry["prefix"],
                                     self.entry["anchor_id"], self.entry["key"], signing_key)
        raise AnchorError("unsupported trusted anchor provider")

    def _cached(self):
        if not self.entry:
            return []
        _no_symlinks(self.cache_dir)
        if not self.cache_dir.exists():
            return []
        result = []
        for path in self.cache_dir.iterdir():
            if path.name.startswith(".snapshot-") and path.name.endswith(".tmp"):
                continue
            if path.suffix != ".json" or not RECEIPT_ID_RE.fullmatch(path.stem):
                raise AnchorError("unexpected cached receipt entry")
            item = parse_json(_read(path))
            if item.get("payload", {}).get("receipt_id") != path.stem:
                raise AnchorError("cached receipt identity mismatch")
            result.append(item)
        return sorted(result, key=lambda item: item["payload"].get("anchor_sequence", -1))

    def anchor_snapshot(self, snapshot_identifier, signing_key, acknowledged_at=None):
        store = SnapshotStore(self.ws, self.snapshot_key)
        chain = store.verify_chain()
        if not chain["valid"]:
            raise AnchorError("local snapshot chain invalid")
        document = store.read(snapshot_identifier)
        if not store.verify_snapshot(snapshot_identifier)["valid"]:
            raise AnchorError("snapshot is not authenticated by the trusted signer")
        # Sequential v1: all predecessors must already be in the external ledger.
        receipt = self.provider(signing_key).anchor(request_from_snapshot(document), acknowledged_at)
        try:
            _publish(self.cache_dir / f"{receipt['payload']['receipt_id']}.json", canonical_bytes(receipt))
        except FileExistsError:
            current = parse_json(_read(self.cache_dir / f"{receipt['payload']['receipt_id']}.json"))
            if current != receipt:
                raise AnchorError("conflicting local receipt cache")
        except Exception:
            raise AnchorError("anchor acknowledged snapshot but local receipt cache failed") from None
        return receipt

    def list_receipts(self):
        return list(self._cached())

    def get_receipt(self, receipt_identifier):
        if not isinstance(receipt_identifier, str) or not RECEIPT_ID_RE.fullmatch(receipt_identifier):
            raise AnchorError("invalid receipt ID")
        try:
            return next(item for item in self._cached()
                        if item["payload"]["receipt_id"] == receipt_identifier)
        except StopIteration:
            raise AnchorError("receipt not found") from None

    def verify_anchor_receipt(self, receipt_identifier):
        if not self.entry:
            return {"valid": False, "receipt_structurally_valid": False,
                    "anchor_trusted": False, "receipt_authentic": False,
                    "errors": ["TRUSTED ANCHOR UNAVAILABLE"]}
        try:
            receipt = self.get_receipt(receipt_identifier)
            return verify_receipt(receipt, self.entry["key"], anchor_id=self.entry["anchor_id"],
                                  incident_id=self.ws.incident_id,
                                  anchor_type=self.entry["anchor_type"])
        except AnchorError:
            return {"valid": False, "receipt_structurally_valid": False,
                    "anchor_trusted": False, "receipt_authentic": False,
                    "errors": ["RECEIPT MISSING OR MALFORMED"]}

    def get_expected_tip(self):
        return self.provider().get_expected_tip(self.ws.incident_id)

    def verify_expected_tip(self):
        return self.health()

    def health(self):
        policy = self.entry["policy"] if self.entry else "OPTIONAL"
        capabilities = None
        if self.entry:
            capabilities = anchor_capabilities(self.entry["anchor_type"])
        result = {"valid": True, "status": "UNANCHORED", "policy": policy,
                  "anchor_id": self.entry["anchor_id"] if self.entry else None,
                  "anchor_capabilities": capabilities,
                  "receipt_present": False, "receipt_structurally_valid": None,
                  "anchor_trusted": None, "receipt_authentic": None,
                  "receipt_matches_snapshot": None, "expected_tip_available": False,
                  "expected_tip_checked": False, "expected_tip_relation": "UNANCHORED",
                  "anchor_policy_satisfied": policy == "OPTIONAL", "receipt_id": None,
                  "anchored_snapshot_id": None, "errors": [], "warnings": []}
        try:
            cached = self._cached()
            if not self.entry:
                # Existing receipt material with no trust configuration is invalid, not absent.
                unknown = self.ws.dir / "anchors"
                if self.config_error or (unknown.exists() and any(unknown.rglob("*.json"))):
                    raise AnchorError("cached receipts exist without trusted anchor configuration")
                return result
            latest_cached = cached[-1] if cached else None
            if latest_cached:
                check = verify_receipt(latest_cached, self.entry["key"], anchor_id=self.entry["anchor_id"],
                                       incident_id=self.ws.incident_id,
                                       anchor_type=self.entry["anchor_type"])
                result.update(receipt_present=True, receipt_structurally_valid=check["receipt_structurally_valid"],
                              anchor_trusted=check["anchor_trusted"], receipt_authentic=check["receipt_authentic"],
                              receipt_id=latest_cached["payload"].get("receipt_id"),
                              anchored_snapshot_id=latest_cached["payload"].get("snapshot_id"))
                if not check["valid"]:
                    raise AnchorError("cached anchor receipt invalid")
                # Every cached item must be authentic and monotonic; deletion is exposed online.
                previous = None
                for index, item in enumerate(cached, 1):
                    check = verify_receipt(item, self.entry["key"], anchor_id=self.entry["anchor_id"],
                                           incident_id=self.ws.incident_id,
                                           anchor_type=self.entry["anchor_type"])
                    p = item["payload"]
                    if (not check["valid"] or p["anchor_sequence"] != index or
                            p["snapshot_sequence"] != index or
                            (previous and (p["previous_receipt_id"] != previous["payload"]["receipt_id"] or
                                           p["previous_receipt_digest"] != receipt_digest(previous) or
                                           p["previous_snapshot_id"] != previous["payload"]["snapshot_id"] or
                                           p["previous_snapshot_digest"] != previous["payload"]["snapshot_digest"]))):
                        raise AnchorError("cached anchor receipt chain invalid")
                    previous = item
            expected = None
            if self.online:
                try:
                    expected = self.provider().get_expected_tip(self.ws.incident_id)
                    result["expected_tip_checked"] = True
                    result["expected_tip_available"] = expected is not None
                except AnchorUnavailable:
                    result["warnings"].append("ANCHOR UNAVAILABLE OR INVALID")
            reference = expected or latest_cached
            if result["expected_tip_checked"] and latest_cached:
                if expected is None:
                    raise AnchorError("external expected tip rolled back behind cached receipt")
                external_sequence = expected["payload"]["anchor_sequence"]
                cached_sequence = latest_cached["payload"]["anchor_sequence"]
                if external_sequence < cached_sequence:
                    raise AnchorError("external expected tip rolled back behind cached receipt")
                if (external_sequence == cached_sequence and
                        expected["payload"]["receipt_id"] != latest_cached["payload"]["receipt_id"]):
                    raise AnchorError("external expected tip conflicts with cached receipt")
            if reference:
                reference_check = verify_receipt(reference, self.entry["key"],
                                                 anchor_id=self.entry["anchor_id"],
                                                 incident_id=self.ws.incident_id,
                                                 anchor_type=self.entry["anchor_type"])
                if not reference_check["valid"]:
                    raise AnchorError("expected anchor receipt invalid")
                result.update(receipt_present=True,
                              receipt_structurally_valid=reference_check["receipt_structurally_valid"],
                              anchor_trusted=reference_check["anchor_trusted"],
                              receipt_authentic=reference_check["receipt_authentic"],
                              receipt_id=reference["payload"]["receipt_id"],
                              anchored_snapshot_id=reference["payload"]["snapshot_id"])
            chain = SnapshotStore(self.ws, self.snapshot_key).verify_chain()
            if not chain["valid"]:
                raise AnchorError("local snapshot chain invalid")
            documents = []
            if chain["latest"]:
                for path in SnapshotStore(self.ws, self.snapshot_key)._paths():
                    documents.append(SnapshotStore(self.ws, self.snapshot_key).read(path.stem))
                documents.sort(key=lambda item: item["payload"]["sequence"])
            if reference is None:
                relation = "UNANCHORED"
            elif not documents:
                relation = "LOCAL_SNAPSHOTS_MISSING"
            else:
                expected_id = reference["payload"]["snapshot_id"]
                ids = [item["payload"]["snapshot_id"] for item in documents]
                if ids[-1] == expected_id:
                    relation = "MATCH"
                elif expected_id in ids:
                    relation = "LOCAL_AHEAD_OF_EXPECTED"
                elif documents[-1]["payload"]["sequence"] < reference["payload"]["snapshot_sequence"]:
                    relation = "LOCAL_BEHIND_EXPECTED"
                else:
                    relation = "DIVERGED"
            result["expected_tip_relation"] = relation
            if relation == "UNANCHORED" and result["warnings"]:
                result["status"] = "ANCHOR_UNAVAILABLE"
            if reference:
                snapshot = next((item for item in documents if item["payload"]["snapshot_id"] == reference["payload"]["snapshot_id"]), None)
                matches = snapshot is not None and request_from_snapshot(snapshot) == {
                    field: reference["payload"][field] for field in REQUEST_FIELDS}
                result["receipt_matches_snapshot"] = matches
                if snapshot is not None and not matches:
                    raise AnchorError("anchor receipt does not match authenticated snapshot")
            if (expected and latest_cached and
                    expected["payload"]["anchor_sequence"] > latest_cached["payload"]["anchor_sequence"]):
                result["warnings"].append("LOCAL RECEIPT CACHE IS STALE")
            required = policy == "REQUIRED" or (policy == "REQUIRED_FOR_SEAL" and self.ws.is_sealed)
            satisfied = (not required and relation in {"UNANCHORED", "MATCH", "LOCAL_AHEAD_OF_EXPECTED"})
            if required:
                satisfied = (result["expected_tip_checked"] and relation == "MATCH" and
                             result["expected_tip_available"] and
                             result["receipt_authentic"] is True and result["receipt_matches_snapshot"] is True)
            if relation in {"LOCAL_BEHIND_EXPECTED", "LOCAL_SNAPSHOTS_MISSING", "DIVERGED"}:
                satisfied = False
            result["anchor_policy_satisfied"] = satisfied
            result["valid"] = satisfied
            if result["status"] != "ANCHOR_UNAVAILABLE":
                result["status"] = relation if satisfied or relation != "UNANCHORED" else "UNANCHORED"
            if not self.online and latest_cached:
                result["status"] = "OFFLINE_RECEIPT_VERIFIED" if satisfied else relation
                result["warnings"].append("EXPECTED TIP NOT CHECKED")
        except Exception:
            result.update(valid=False, anchor_policy_satisfied=False, status="INVALID")
            result["errors"].append("ANCHOR RECEIPT OR POLICY VERIFICATION FAILED")
        return result


def report_section(health):
    lines = ["## Independent checkpoint anchor", "", f"- Policy: {health['policy']}",
             f"- Anchor status: {health['status']}", f"- Anchor ID: {health.get('anchor_id')}",
             f"- Anchor provider: {(health.get('anchor_capabilities') or {}).get('provider')}",
             f"- Retention verified by Coreline: {(health.get('anchor_capabilities') or {}).get('retention_verified')}",
             f"- Receipt ID: {health.get('receipt_id')}",
             f"- Anchored snapshot: {health.get('anchored_snapshot_id')}",
             f"- Receipt authentic: {health.get('receipt_authentic')}",
             f"- Expected tip checked: {health.get('expected_tip_checked')}",
             f"- Expected tip relation: {health.get('expected_tip_relation')}",
             f"- Policy satisfied: {health.get('anchor_policy_satisfied')}", ""]
    return "\n".join(lines)
