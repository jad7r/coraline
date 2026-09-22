"""Google Cloud Storage adapter for independently retained snapshot receipts.

This is deliberately separate from the write-only evidence backend.  Anchor
freshness requires bounded reads and listing.  Production construction uses ambient
ADC only; retention and IAM remain externally configured deployment properties.
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone

from core.evidence._util import to_iso
from core.evidence.integrity import signing
from .snapshots import MAX_BYTES, canonical_bytes, parse_json
from .anchors import (
    AnchorError, AnchorUnavailable, DOMAIN, PREFIX, REQUEST_FIELDS,
    _validate_request, anchor_capabilities, receipt_digest, receipt_id, verify_receipt,
)

_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,221}[a-z0-9]\Z")
_PREFIX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,511}\Z")
_SEQUENCE_RE = re.compile(r"[0-9]{20}\.json\Z")


def validate_gcs_location(bucket, prefix):
    if (not isinstance(bucket, str) or not _BUCKET_RE.fullmatch(bucket) or
            not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix) or
            prefix.startswith("/") or prefix.endswith("/") or "//" in prefix or
            any(part in {".", ".."} for part in prefix.split("/"))):
        raise AnchorError("invalid GCS anchor location")


class GCSAnchor:
    """Append-only receipt ledger using create-only GCS sequence objects."""

    def __init__(self, bucket, prefix, anchor_id, verify_key, signing_key=None, *, client):
        from .anchors import ANCHOR_ID_RE
        validate_gcs_location(bucket, prefix)
        if not ANCHOR_ID_RE.fullmatch(anchor_id):
            raise AnchorError("invalid anchor identity")
        self.bucket, self.prefix, self.anchor_id = bucket, prefix, anchor_id
        self.verify_key, self.signing_key, self._client = verify_key, signing_key, client

    @classmethod
    def keyless(cls, bucket, prefix, anchor_id, verify_key, signing_key=None):
        """Construct with ambient ADC/WIF. No credential or key-file argument exists."""
        from google.cloud import storage
        return cls(bucket, prefix, anchor_id, verify_key, signing_key,
                   client=storage.Client())

    def capabilities(self):
        return anchor_capabilities("gcs-v1")

    def _ledger_prefix(self, incident_id):
        digest = hashlib.sha256(incident_id.encode("utf-8")).hexdigest()
        return f"{self.prefix}/{self.anchor_id}/ledger/{digest}/"

    def _name(self, incident_id, sequence):
        return self._ledger_prefix(incident_id) + f"{sequence:020d}.json"

    def _read_blob(self, name):
        try:
            data = self._client.bucket(self.bucket).blob(name).download_as_bytes()
        except Exception:
            raise AnchorUnavailable("GCS anchor object unavailable") from None
        try:
            if not isinstance(data, bytes) or len(data) > MAX_BYTES:
                raise ValueError()
            return parse_json(data)
        except Exception:
            raise AnchorError("GCS anchor object malformed") from None

    def _objects(self, incident_id):
        prefix = self._ledger_prefix(incident_id)
        try:
            blobs = list(self._client.list_blobs(self.bucket, prefix=prefix))
        except Exception:
            raise AnchorUnavailable("GCS anchor listing unavailable") from None
        names = []
        for blob in blobs:
            name = getattr(blob, "name", None)
            tail = name[len(prefix):] if isinstance(name, str) and name.startswith(prefix) else ""
            if not _SEQUENCE_RE.fullmatch(tail):
                raise AnchorError("unexpected GCS anchor ledger entry")
            names.append(name)
        if len(names) != len(set(names)):
            raise AnchorError("duplicate GCS anchor ledger entry")
        return sorted(names)

    def verify_ledger(self, incident_id):
        result = {"valid": False, "count": 0, "latest": None, "errors": []}
        try:
            previous = None
            count = 0
            for index, name in enumerate(self._objects(incident_id), 1):
                if name != self._name(incident_id, index):
                    raise AnchorError("non-monotonic GCS anchor ledger")
                item = self._read_blob(name)
                check = verify_receipt(item, self.verify_key, anchor_id=self.anchor_id,
                                       incident_id=incident_id, anchor_type="gcs-v1")
                p = item.get("payload", {})
                if (not check["valid"] or p.get("anchor_sequence") != index or
                        p.get("snapshot_sequence") != index):
                    raise AnchorError("invalid GCS anchor receipt")
                if previous and (p["previous_receipt_id"] != previous["payload"]["receipt_id"] or
                                 p["previous_receipt_digest"] != receipt_digest(previous) or
                                 p["previous_snapshot_id"] != previous["payload"]["snapshot_id"] or
                                 p["previous_snapshot_digest"] != previous["payload"]["snapshot_digest"]):
                    raise AnchorError("GCS anchor ledger linkage mismatch")
                previous = item
                count = index
            result.update(valid=True, count=count, latest=previous)
        except AnchorUnavailable:
            result.update(unavailable=True, errors=["ANCHOR UNAVAILABLE"])
        except Exception:
            result.update(unavailable=False, errors=["ANCHOR LEDGER BROKEN OR UNAVAILABLE"])
        return result

    def get_expected_tip(self, incident_id):
        ledger = self.verify_ledger(incident_id)
        if not ledger["valid"]:
            if ledger.get("unavailable"):
                raise AnchorUnavailable("GCS expected tip unavailable")
            raise AnchorError("GCS expected tip unavailable or invalid")
        return ledger["latest"]

    def anchor(self, request, acknowledged_at=None):
        _validate_request(request)
        if (self.signing_key is None or
                signing.key_fingerprint(self.signing_key.verify_key) !=
                signing.key_fingerprint(self.verify_key)):
            raise AnchorError("anchor signing authority unavailable or untrusted")
        ledger = self.verify_ledger(request["incident_id"])
        if not ledger["valid"]:
            raise AnchorError("existing GCS anchor ledger invalid")
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
                   "anchor_id": self.anchor_id, "anchor_type": "gcs-v1",
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
                              incident_id=request["incident_id"], anchor_type="gcs-v1")["valid"]:
            raise AnchorError("new GCS anchor receipt verification failed")
        encoded = canonical_bytes(receipt)
        if len(encoded) > MAX_BYTES:
            raise AnchorError("anchor receipt exceeds supported size")
        name = self._name(request["incident_id"], expected)
        try:
            self._client.bucket(self.bucket).blob(name).upload_from_string(
                encoded, content_type="application/json", if_generation_match=0)
            return receipt
        except Exception:
            # A concurrent identical writer may have won the create-only object.
            try:
                existing = self._read_blob(name)
                if (verify_receipt(existing, self.verify_key, anchor_id=self.anchor_id,
                                   incident_id=request["incident_id"], anchor_type="gcs-v1")["valid"] and
                        all(existing["payload"][field] == request[field] for field in REQUEST_FIELDS)):
                    return existing
            except Exception:
                pass
            raise AnchorError("GCS anchor operation failed without modifying incident state") from None
