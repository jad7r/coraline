"""Signed, monotonic public-key trust registry releases.

The registry root is pinned outside release content. Releases contain public keys
only and authorize snapshot and anchor signing; they never store private material.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from core.evidence._util import to_iso
from core.evidence.integrity import signing
from .snapshots import HASH_RE, MAX_BYTES, _no_symlinks, _publish, _read, canonical_bytes, parse_json

DOMAIN = "coreline.trust-registry-release.v1"
TIP_DOMAIN = "coreline.trust-registry-expected-tip.v1"
PREFIX = (DOMAIN + "\0").encode()
TIP_PREFIX = (TIP_DOMAIN + "\0").encode()
RELEASE_ID_RE = re.compile(r"TRR-[0-9a-f]{64}\Z")
REGISTRY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
KEY_STATUSES = {"ACTIVE", "RETIRED", "REVOKED"}
KEY_PURPOSES = {"SNAPSHOT_SIGNER", "ANCHOR_SIGNER"}
RELEASE_FIELDS = {"domain", "schema_version", "registry_id", "generation", "release_id",
                  "previous_release_id", "previous_release_digest", "created_at", "created_by",
                  "transition", "keys", "root_key_id", "signature_algorithm"}
KEY_FIELDS = {"key_id", "purpose", "scope", "identity", "verify_key", "status",
              "introduced_generation", "status_generation", "reason"}
BINDING_FIELDS = {"registry_id", "generation", "release_id", "release_digest", "root_key_id"}
_THREAD_LOCKS = {}
_THREAD_LOCKS_GUARD = threading.Lock()


class TrustRegistryError(Exception):
    """Value-free trust registry failure suitable for operator output."""


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def release_id(payload):
    return "TRR-" + _hash(canonical_bytes({k: v for k, v in payload.items() if k != "release_id"}))


def release_digest(document):
    return _hash(canonical_bytes(document))


def root_path(home):
    return Path(os.environ.get("CORELINE_TRUST_ROOT") or Path(home) / "trust" / "registry-root.json")


def releases_path(home):
    return Path(os.environ.get("CORELINE_TRUST_RELEASES") or Path(home) / "trust" / "registry-releases")


def expected_tip_path(home):
    value = os.environ.get("CORELINE_TRUST_EXPECTED_TIP")
    return Path(value) if value else None


def _strict_time(value):
    return (isinstance(value, str) and value.endswith("Z") and
            to_iso(datetime.fromisoformat(value.replace("Z", "+00:00"))) == value)


def _decode_key_record(item):
    if not isinstance(item, dict) or set(item) != KEY_FIELDS:
        raise TrustRegistryError("invalid trust key record")
    if (item["purpose"] not in KEY_PURPOSES or item["status"] not in KEY_STATUSES or
            not isinstance(item["scope"], str) or not item["scope"] or
            not isinstance(item["identity"], str) or not item["identity"] or
            type(item["introduced_generation"]) is not int or item["introduced_generation"] < 1 or
            type(item["status_generation"]) is not int or item["status_generation"] < item["introduced_generation"] or
            (item["reason"] is not None and (not isinstance(item["reason"], str) or not item["reason"].strip()))):
        raise TrustRegistryError("invalid trust key record")
    try:
        key = signing.decode_verify_key(item["verify_key"])
    except Exception:
        raise TrustRegistryError("invalid trust verification key") from None
    if item["key_id"] != signing.key_fingerprint(key):
        raise TrustRegistryError("trust key identity mismatch")
    return key


def _validate_payload(payload):
    if not isinstance(payload, dict) or set(payload) != RELEASE_FIELDS:
        raise TrustRegistryError("invalid registry release")
    if (payload["domain"] != DOMAIN or payload["schema_version"] != 1 or
            not REGISTRY_ID_RE.fullmatch(payload["registry_id"]) or
            type(payload["generation"]) is not int or payload["generation"] < 1 or
            not _strict_time(payload["created_at"]) or
            not isinstance(payload["created_by"], str) or not payload["created_by"] or
            payload["signature_algorithm"] != "ed25519" or
            not isinstance(payload["transition"], dict) or
            set(payload["transition"]) != {"kind", "reason"} or
            payload["transition"]["kind"] not in {"BOOTSTRAP", "UPDATE", "ROTATION", "REVOCATION", "TRUST_RESET"} or
            (payload["transition"]["reason"] is not None and
             (not isinstance(payload["transition"]["reason"], str) or not payload["transition"]["reason"].strip()))):
        raise TrustRegistryError("invalid registry release")
    if payload["generation"] == 1:
        if payload["previous_release_id"] is not None or payload["previous_release_digest"] is not None:
            raise TrustRegistryError("invalid initial registry release")
    elif (not RELEASE_ID_RE.fullmatch(payload["previous_release_id"] or "") or
          not re.fullmatch(r"[0-9a-f]{64}", payload["previous_release_digest"] or "")):
        raise TrustRegistryError("invalid registry predecessor")
    if not isinstance(payload["keys"], list):
        raise TrustRegistryError("invalid registry keys")
    seen = set()
    active = set()
    for item in payload["keys"]:
        _decode_key_record(item)
        if (item["introduced_generation"] > payload["generation"] or
                item["status_generation"] > payload["generation"]):
            raise TrustRegistryError("trust key generation exceeds release")
        if item["key_id"] in seen:
            raise TrustRegistryError("duplicate registry key")
        seen.add(item["key_id"])
        slot = (item["purpose"], item["scope"])
        if item["status"] == "ACTIVE" and slot in active:
            raise TrustRegistryError("multiple active keys for trust purpose")
        if item["status"] == "ACTIVE":
            active.add(slot)
    if not RELEASE_ID_RE.fullmatch(payload["release_id"] or "") or payload["release_id"] != release_id(payload):
        raise TrustRegistryError("registry release identity mismatch")
    canonical_bytes(payload)


def verify_release(document, root_key, *, registry_id=None):
    result = {"valid": False, "structure_valid": False, "root_trusted": False,
              "signature_valid": False, "errors": []}
    try:
        if not isinstance(document, dict) or set(document) != {"payload", "signature"}:
            raise TrustRegistryError("invalid release envelope")
        payload = document["payload"]
        _validate_payload(payload)
        if registry_id is not None and payload["registry_id"] != registry_id:
            raise TrustRegistryError("registry identity mismatch")
        signature = base64.b64decode(document["signature"], validate=True)
        if len(signature) != signing.SIGNATURE_BYTES:
            raise TrustRegistryError("invalid release signature")
        result["structure_valid"] = True
        result["root_trusted"] = (root_key is not None and
                                  payload["root_key_id"] == signing.key_fingerprint(root_key))
        result["signature_valid"] = result["root_trusted"] and signing.verify(
            PREFIX + canonical_bytes(payload), signature, root_key)
        if not result["root_trusted"]:
            result["errors"].append("UNKNOWN REGISTRY ROOT")
        elif not result["signature_valid"]:
            result["errors"].append("REGISTRY SIGNATURE INVALID")
    except Exception:
        result["errors"].append("INVALID REGISTRY RELEASE")
    result["valid"] = all(result[k] for k in ("structure_valid", "root_trusted", "signature_valid"))
    return result


def write_root_pin(path, registry_id, root_key, expected_tip=None):
    if not REGISTRY_ID_RE.fullmatch(registry_id):
        raise TrustRegistryError("invalid registry identity")
    payload = {"schema_version": 1, "registry_id": registry_id,
               "root_key_id": signing.key_fingerprint(root_key),
               "verify_key": signing.encode_verify_key(root_key)}
    if expected_tip is not None:
        payload["expected_tip"] = str(Path(expected_tip).resolve())
    try:
        _publish(Path(path), canonical_bytes(payload), 0o600)
    except Exception:
        raise TrustRegistryError("registry root pin could not be created") from None


def load_root_pin(path, *, incident_dir=None):
    try:
        path = Path(path)
        if incident_dir is not None and path.resolve().is_relative_to(Path(incident_dir).resolve()):
            raise ValueError()
        data = parse_json(_read(path))
        if (set(data) not in ({"schema_version", "registry_id", "root_key_id", "verify_key"},
                              {"schema_version", "registry_id", "root_key_id", "verify_key", "expected_tip"}) or
                data["schema_version"] != 1):
            raise ValueError()
        if not REGISTRY_ID_RE.fullmatch(data["registry_id"]):
            raise ValueError()
        key = signing.decode_verify_key(data["verify_key"])
        if data["root_key_id"] != signing.key_fingerprint(key):
            raise ValueError()
        if "expected_tip" in data and (not isinstance(data["expected_tip"], str) or
                                       not Path(data["expected_tip"]).is_absolute()):
            raise ValueError()
        return {**data, "key": key}
    except Exception:
        raise TrustRegistryError("registry root pin unavailable or invalid") from None


class TrustRegistryStore:
    def __init__(self, release_dir, root_pin, expected_tip_dir=None):
        self.directory = Path(release_dir)
        self.pin = root_pin
        self.expected_dir = Path(expected_tip_dir) if expected_tip_dir else None

    @classmethod
    def discover(cls, home, *, incident_dir=None):
        pin_path = root_path(home)
        if not pin_path.exists():
            return None
        pin = load_root_pin(pin_path, incident_dir=incident_dir)
        release_dir = releases_path(home)
        expected = expected_tip_path(home) or (Path(pin["expected_tip"]) if pin.get("expected_tip") else None)
        if incident_dir is not None:
            incident = Path(incident_dir).resolve()
            if release_dir.resolve().is_relative_to(incident) or (expected and expected.resolve().is_relative_to(incident)):
                raise TrustRegistryError("trust material cannot reside inside an incident")
        return cls(release_dir, pin, expected)

    @contextmanager
    def _lock(self):
        _no_symlinks(self.directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / ".registry.lock"
        _no_symlinks(path)
        lock_key = str(path.resolve())
        with _THREAD_LOCKS_GUARD:
            thread_lock = _THREAD_LOCKS.setdefault(lock_key, threading.Lock())
        with thread_lock:
            with path.open("a+", encoding="utf-8") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _paths(self):
        _no_symlinks(self.directory)
        if not self.directory.exists():
            return []
        paths = []
        for path in self.directory.iterdir():
            if path.name == ".registry.lock" or (path.name.startswith(".snapshot-") and path.name.endswith(".tmp")):
                continue
            if path.suffix != ".json" or not RELEASE_ID_RE.fullmatch(path.stem):
                raise TrustRegistryError("unexpected registry release entry")
            paths.append(path)
        return sorted(paths)

    def read(self, identifier):
        if not isinstance(identifier, str) or not RELEASE_ID_RE.fullmatch(identifier):
            raise TrustRegistryError("invalid registry release ID")
        try:
            return parse_json(_read(self.directory / f"{identifier}.json"))
        except Exception:
            raise TrustRegistryError("registry release unreadable or malformed") from None

    def verify_chain(self):
        result = {"valid": False, "count": 0, "latest": None, "errors": []}
        try:
            documents = []
            for path in self._paths():
                item = self.read(path.stem)
                check = verify_release(item, self.pin["key"], registry_id=self.pin["registry_id"])
                if not check["valid"] or item["payload"]["release_id"] != path.stem:
                    raise TrustRegistryError("invalid registry release")
                documents.append(item)
            documents.sort(key=lambda item: item["payload"]["generation"])
            previous = None
            for generation, item in enumerate(documents, 1):
                p = item["payload"]
                if p["generation"] != generation:
                    raise TrustRegistryError("missing or duplicate registry generation")
                if previous and (p["previous_release_id"] != previous["payload"]["release_id"] or
                                 p["previous_release_digest"] != release_digest(previous)):
                    raise TrustRegistryError("registry release chain broken")
                self._validate_transition(previous, item)
                previous = item
            result.update(valid=True, count=len(documents), latest=previous)
        except Exception:
            result["errors"].append("REGISTRY CHAIN BROKEN OR UNREADABLE")
        return result

    def _validate_transition(self, previous, current):
        current_keys = {item["key_id"]: item for item in current["payload"]["keys"]}
        if previous is None:
            if current["payload"]["transition"]["kind"] not in {"BOOTSTRAP", "TRUST_RESET"}:
                raise TrustRegistryError("invalid registry bootstrap")
            return
        if current["payload"]["transition"]["kind"] in {"BOOTSTRAP", "TRUST_RESET"}:
            raise TrustRegistryError("bootstrap transition cannot follow existing trust")
        old = {item["key_id"]: item for item in previous["payload"]["keys"]}
        if set(old) - set(current_keys):
            raise TrustRegistryError("registry keys cannot be deleted")
        revoked = False
        retired_slots = set()
        for key_id, before in old.items():
            after = current_keys[key_id]
            immutable = KEY_FIELDS - {"status", "status_generation", "reason"}
            if any(before[field] != after[field] for field in immutable):
                raise TrustRegistryError("registry key identity changed")
            allowed = {"ACTIVE": {"ACTIVE", "RETIRED", "REVOKED"},
                       "RETIRED": {"RETIRED", "REVOKED"}, "REVOKED": {"REVOKED"}}
            if after["status"] not in allowed[before["status"]]:
                raise TrustRegistryError("registry key status rollback")
            changed = after["status"] != before["status"]
            if changed != (after["status_generation"] == current["payload"]["generation"]):
                raise TrustRegistryError("registry status boundary invalid")
            if not changed and (after["status_generation"] != before["status_generation"] or
                                after["reason"] != before["reason"]):
                raise TrustRegistryError("registry transition metadata changed")
            if changed and (not after["reason"] or not after["reason"].strip()):
                raise TrustRegistryError("registry transition reason missing")
            if changed and after["status"] == "REVOKED":
                revoked = True
            if changed and after["status"] == "RETIRED":
                retired_slots.add((after["purpose"], after["scope"]))
        new_slots = set()
        for key_id in set(current_keys) - set(old):
            item = current_keys[key_id]
            if item["introduced_generation"] != current["payload"]["generation"] or item["status"] != "ACTIVE":
                raise TrustRegistryError("new registry key must enter active")
            new_slots.add((item["purpose"], item["scope"]))
        kind = current["payload"]["transition"]["kind"]
        if revoked and kind != "REVOCATION":
            raise TrustRegistryError("revocation transition mislabeled")
        if retired_slots & new_slots and kind != "ROTATION":
            raise TrustRegistryError("rotation transition mislabeled")
        if kind == "REVOCATION" and not revoked:
            raise TrustRegistryError("revocation transition has no revocation")
        if kind == "ROTATION" and not (retired_slots & new_slots):
            raise TrustRegistryError("rotation transition has no replacement")

    def create_release(self, root_signing_key, actor, keys, *, kind="UPDATE", reason=None, when=None):
        if (signing.key_fingerprint(root_signing_key.verify_key) != self.pin["root_key_id"] or
                not actor or not actor.strip()):
            raise TrustRegistryError("registry release authority unavailable")
        with self._lock():
            chain = self.verify_chain()
            if not chain["valid"]:
                raise TrustRegistryError("existing registry chain invalid")
            previous = chain["latest"]
            generation = chain["count"] + 1
            normalized_keys = sorted(keys, key=lambda item: item["key_id"])
            if (previous and previous["payload"]["keys"] == normalized_keys and
                    previous["payload"]["transition"] == {"kind": kind, "reason": reason}):
                if self.expected_dir is not None:
                    self._publish_expected_tip(previous, root_signing_key)
                return previous
            if generation == 1 and kind not in {"BOOTSTRAP", "TRUST_RESET"}:
                kind = "BOOTSTRAP"
            payload = {"domain": DOMAIN, "schema_version": 1,
                       "registry_id": self.pin["registry_id"], "generation": generation,
                       "previous_release_id": previous["payload"]["release_id"] if previous else None,
                       "previous_release_digest": release_digest(previous) if previous else None,
                       "created_at": to_iso(when or datetime.now(timezone.utc)), "created_by": actor.strip(),
                       "transition": {"kind": kind, "reason": reason},
                       "keys": normalized_keys,
                       "root_key_id": self.pin["root_key_id"], "signature_algorithm": "ed25519"}
            payload["release_id"] = release_id(payload)
            document = {"payload": payload, "signature": base64.b64encode(
                signing.sign(PREFIX + canonical_bytes(payload), root_signing_key)).decode("ascii")}
            if not verify_release(document, self.pin["key"], registry_id=self.pin["registry_id"])["valid"]:
                raise TrustRegistryError("new registry release verification failed")
            self._validate_transition(previous, document)
            encoded = canonical_bytes(document)
            if len(encoded) > MAX_BYTES:
                raise TrustRegistryError("registry release exceeds supported size")
            _publish(self.directory / f"{payload['release_id']}.json", encoded)
            if self.expected_dir is not None:
                self._publish_expected_tip(document, root_signing_key)
            return document

    def _publish_expected_tip(self, release, root_signing_key):
        p = release["payload"]
        payload = {"domain": TIP_DOMAIN, "schema_version": 1, "registry_id": p["registry_id"],
                   "generation": p["generation"], "release_id": p["release_id"],
                   "release_digest": release_digest(release), "root_key_id": p["root_key_id"],
                   "recorded_at": p["created_at"], "signature_algorithm": "ed25519"}
        doc = {"payload": payload, "signature": base64.b64encode(
            signing.sign(TIP_PREFIX + canonical_bytes(payload), root_signing_key)).decode("ascii")}
        directory = self.expected_dir / hashlib.sha256(p["registry_id"].encode()).hexdigest()
        path = directory / f"{p['generation']:020d}.json"
        try:
            _publish(path, canonical_bytes(doc))
        except FileExistsError:
            if parse_json(_read(path)) != doc:
                raise TrustRegistryError("conflicting expected registry tip")

    def expected_tip(self):
        if self.expected_dir is None:
            return {"checked": False, "available": False, "valid": None, "relation": "NOT_CONFIGURED"}
        try:
            directory = self.expected_dir / hashlib.sha256(self.pin["registry_id"].encode()).hexdigest()
            _no_symlinks(directory)
            paths = sorted(directory.glob("*.json")) if directory.exists() else []
            if not paths:
                return {"checked": True, "available": False, "valid": True, "relation": "NOT_PRESENT"}
            previous_generation = 0
            latest = None
            for path in paths:
                if not re.fullmatch(r"[0-9]{20}\.json", path.name):
                    raise ValueError()
                doc = parse_json(_read(path)); payload = doc["payload"]
                required = {"domain", "schema_version", "registry_id", "generation", "release_id",
                            "release_digest", "root_key_id", "recorded_at", "signature_algorithm"}
                if (set(doc) != {"payload", "signature"} or set(payload) != required or
                        payload["domain"] != TIP_DOMAIN or payload["schema_version"] != 1 or
                        payload["registry_id"] != self.pin["registry_id"] or
                        payload["generation"] != previous_generation + 1 or
                        path.name != f"{payload['generation']:020d}.json" or
                        payload["root_key_id"] != self.pin["root_key_id"] or
                        not signing.verify(TIP_PREFIX + canonical_bytes(payload),
                                           base64.b64decode(doc["signature"], validate=True), self.pin["key"])):
                    raise ValueError()
                previous_generation = payload["generation"]; latest = payload
            chain = self.verify_chain(); local = chain["latest"]
            if not chain["valid"]:
                relation = "LOCAL_INVALID"
            elif local is None:
                relation = "LOCAL_MISSING"
            elif local["payload"]["generation"] < latest["generation"]:
                relation = "LOCAL_BEHIND_EXPECTED"
            elif local["payload"]["generation"] > latest["generation"]:
                relation = "LOCAL_AHEAD_OF_EXPECTED"
            elif (local["payload"]["release_id"] == latest["release_id"] and
                  release_digest(local) == latest["release_digest"]):
                relation = "MATCH"
            else:
                relation = "DIVERGED"
            return {"checked": True, "available": True, "valid": relation in {"MATCH", "LOCAL_AHEAD_OF_EXPECTED"},
                    "relation": relation, "expected": latest}
        except OSError:
            return {"checked": False, "available": False, "valid": None, "relation": "UNAVAILABLE"}
        except Exception:
            return {"checked": True, "available": True, "valid": False, "relation": "INVALID"}

    def latest_keys(self):
        chain = self.verify_chain()
        if not chain["valid"] or chain["latest"] is None:
            raise TrustRegistryError("trusted registry unavailable")
        return chain["latest"]["payload"]["keys"]

    def binding_for_release(self, release):
        """Return the closed artifact binding for an authenticated local release."""
        try:
            payload = release["payload"]
            binding = {
                "registry_id": payload["registry_id"],
                "generation": payload["generation"],
                "release_id": payload["release_id"],
                "release_digest": release_digest(release),
                "root_key_id": payload["root_key_id"],
            }
            if self.resolve_binding(binding) != release:
                raise TrustRegistryError("registry release binding mismatch")
            return binding
        except TrustRegistryError:
            raise
        except Exception:
            raise TrustRegistryError("registry release binding mismatch") from None

    def resolve_binding(self, binding):
        """Resolve an artifact binding only through the pinned, verified chain."""
        try:
            if (not isinstance(binding, dict) or set(binding) != BINDING_FIELDS or
                    binding["registry_id"] != self.pin["registry_id"] or
                    binding["root_key_id"] != self.pin["root_key_id"] or
                    type(binding["generation"]) is not int or binding["generation"] < 1 or
                    not RELEASE_ID_RE.fullmatch(binding["release_id"]) or
                    not HASH_RE.fullmatch(binding["release_digest"])):
                raise ValueError()
            chain = self.verify_chain()
            if not chain["valid"] or binding["generation"] > chain["count"]:
                raise ValueError()
            release = self.read(binding["release_id"])
            payload = release["payload"]
            if (payload["generation"] != binding["generation"] or
                    payload["registry_id"] != binding["registry_id"] or
                    payload["root_key_id"] != binding["root_key_id"] or
                    release_digest(release) != binding["release_digest"]):
                raise ValueError()
            return release
        except Exception:
            raise TrustRegistryError("registry release binding mismatch") from None

    def classify_key_at(self, binding, key_id, purpose, scope):
        """Classify a key in the exact authenticated release named by a binding."""
        release = self.resolve_binding(binding)
        item = next((record for record in release["payload"]["keys"]
                     if record["key_id"] == key_id and record["purpose"] == purpose and
                     record["scope"] == scope), None)
        if item is None:
            return {"classification": "UNKNOWN_KEY", "trusted": False,
                    "key": None, "record": None}
        classification = {"ACTIVE": "TRUSTED_ACTIVE", "RETIRED": "SIGNED_BY_RETIRED_KEY",
                          "REVOKED": "SIGNED_BY_REVOKED_KEY"}[item["status"]]
        return {"classification": classification, "trusted": item["status"] in {"ACTIVE", "RETIRED"},
                "key": signing.decode_verify_key(item["verify_key"]), "record": item}

    def key_record(self, key_id, purpose=None, scope=None):
        for item in self.latest_keys():
            if (item["key_id"] == key_id and (purpose is None or item["purpose"] == purpose) and
                    (scope is None or item["scope"] == scope)):
                return item
        return None

    def classify_key(self, key_id, purpose, scope):
        item = self.key_record(key_id, purpose, scope)
        if item is None:
            return {"classification": "UNKNOWN_KEY", "trusted": False, "key": None, "record": None}
        classification = {"ACTIVE": "TRUSTED_ACTIVE", "RETIRED": "SIGNED_BY_RETIRED_KEY",
                          "REVOKED": "SIGNED_BY_REVOKED_KEY"}[item["status"]]
        return {"classification": classification, "trusted": item["status"] in {"ACTIVE", "RETIRED"},
                "key": signing.decode_verify_key(item["verify_key"]), "record": item}

    def authorize(self, signing_key, purpose, scope):
        result = self.classify_key(signing.key_fingerprint(signing_key.verify_key), purpose, scope)
        if result["classification"] != "TRUSTED_ACTIVE":
            raise TrustRegistryError("signing key is not active for this purpose")
        return result

    def active_key(self, purpose, scope):
        records = [item for item in self.latest_keys()
                   if item["purpose"] == purpose and item["scope"] == scope and item["status"] == "ACTIVE"]
        if len(records) != 1:
            raise TrustRegistryError("active trust key unavailable or ambiguous")
        return signing.decode_verify_key(records[0]["verify_key"])

    def health(self, require_expected=False):
        chain = self.verify_chain(); tip = self.expected_tip()
        tip_integrity = not tip["checked"] or not tip["available"] or tip["valid"] is True
        expected_satisfied = (tip["checked"] and tip["available"] and tip["relation"] == "MATCH")
        valid = chain["valid"] and tip_integrity and (not require_expected or expected_satisfied)
        return {"valid": valid, "chain_valid": chain["valid"], "generation": chain["count"],
                "latest_release_id": chain["latest"]["payload"]["release_id"] if chain["latest"] else None,
                "root_key_id": self.pin["root_key_id"], "expected_tip": tip,
                "errors": chain["errors"]}

    def export_bundle(self):
        chain = self.verify_chain()
        if not chain["valid"] or not chain["latest"]:
            raise TrustRegistryError("registry chain unavailable for export")
        releases = [self.read(path.stem) for path in self._paths()]
        releases.sort(key=lambda item: item["payload"]["generation"])
        return {"bundle_schema_version": 1, "registry_id": self.pin["registry_id"],
                "root_key_id": self.pin["root_key_id"],
                "root_verify_key": signing.encode_verify_key(self.pin["key"]),
                "releases": releases}

    def import_bundle(self, bundle):
        if (not isinstance(bundle, dict) or
                set(bundle) != {"bundle_schema_version", "registry_id", "root_key_id",
                                "root_verify_key", "releases"} or
                bundle["bundle_schema_version"] != 1 or bundle["registry_id"] != self.pin["registry_id"] or
                bundle["root_key_id"] != self.pin["root_key_id"] or
                bundle["root_verify_key"] != signing.encode_verify_key(self.pin["key"]) or
                not isinstance(bundle["releases"], list)):
            raise TrustRegistryError("invalid registry bundle identity")
        documents = list(bundle["releases"])
        documents.sort(key=lambda item: item.get("payload", {}).get("generation", -1))
        previous = None
        for generation, item in enumerate(documents, 1):
            check = verify_release(item, self.pin["key"], registry_id=self.pin["registry_id"])
            p = item.get("payload", {})
            if (not check["valid"] or p.get("generation") != generation or
                    (previous and (p["previous_release_id"] != previous["payload"]["release_id"] or
                                   p["previous_release_digest"] != release_digest(previous)))):
                raise TrustRegistryError("registry bundle chain invalid")
            self._validate_transition(previous, item)
            previous = item
        if previous is None:
            raise TrustRegistryError("empty registry bundle")
        with self._lock():
            local = self.verify_chain()
            if not local["valid"]:
                raise TrustRegistryError("local registry chain invalid")
            if len(documents) < local["count"]:
                raise TrustRegistryError("registry bundle rollback rejected")
            local_documents = sorted((self.read(path.stem) for path in self._paths()),
                                     key=lambda item: item["payload"]["generation"])
            for generation in range(local["count"]):
                if local_documents[generation] != documents[generation]:
                    raise TrustRegistryError("registry bundle conflicts with trusted history")
            for item in documents[local["count"]:]:
                _publish(self.directory / f"{item['payload']['release_id']}.json", canonical_bytes(item))
        return previous


def make_key_record(verify_key, purpose, scope, identity, generation, *, status="ACTIVE", reason=None):
    if purpose not in KEY_PURPOSES or status not in KEY_STATUSES:
        raise TrustRegistryError("invalid trust key purpose or status")
    item = {"key_id": signing.key_fingerprint(verify_key), "purpose": purpose, "scope": scope,
            "identity": identity, "verify_key": signing.encode_verify_key(verify_key),
            "status": status, "introduced_generation": generation,
            "status_generation": generation, "reason": reason}
    _decode_key_record(item)
    return item


def transition_keys(keys, key_id, status, generation, reason):
    if status not in {"RETIRED", "REVOKED"} or not reason or not reason.strip():
        raise TrustRegistryError("trust transition requires status and reason")
    result = []
    found = False
    for item in keys:
        item = dict(item)
        if item["key_id"] == key_id:
            found = True
            allowed = {"ACTIVE": {"RETIRED", "REVOKED"}, "RETIRED": {"REVOKED"}, "REVOKED": set()}
            if status not in allowed[item["status"]]:
                raise TrustRegistryError("invalid trust key transition")
            item.update(status=status, status_generation=generation, reason=reason.strip())
        result.append(item)
    if not found:
        raise TrustRegistryError("unknown trust key")
    return result


def trust_health(home, *, incident_dir=None, require_expected=False):
    if not root_path(home).exists():
        return {"valid": True, "status": "NOT_PRESENT", "chain_valid": None,
                "generation": 0, "latest_release_id": None, "root_key_id": None,
                "expected_tip": {"checked": False, "available": False, "valid": None,
                                 "relation": "NOT_CONFIGURED"}, "errors": []}
    try:
        store = TrustRegistryStore.discover(home, incident_dir=incident_dir)
        result = store.health(require_expected=require_expected)
        result["status"] = ("VALID" if result["valid"] else
                            result["expected_tip"].get("relation", "INVALID"))
        return result
    except Exception:
        return {"valid": False, "status": "INVALID", "chain_valid": False,
                "generation": 0, "latest_release_id": None, "root_key_id": None,
                "expected_tip": {"checked": False, "available": False, "valid": False,
                                 "relation": "UNKNOWN"},
                "errors": ["TRUST REGISTRY UNAVAILABLE OR INVALID"]}


def report_section(health):
    tip = health.get("expected_tip") or {}
    return "\n".join([
        "## Signed trust registry", "",
        f"- Status: {health.get('status')}",
        f"- Generation: {health.get('generation')}",
        f"- Latest release: {health.get('latest_release_id')}",
        f"- Root key: {health.get('root_key_id')}",
        f"- Chain valid: {health.get('chain_valid')}",
        f"- Expected tip checked: {tip.get('checked')}",
        f"- Expected tip relation: {tip.get('relation')}", "",
    ])
