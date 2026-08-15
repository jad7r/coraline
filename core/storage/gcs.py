"""
GCSWormBackend — write-only Google Cloud Storage backend (Phase 1H Task 2).

Deposits bytes into a bucket-locked (retention-locked) GCS bucket and returns a Receipt
carrying the storage-assigned **generation** number. The interface is write-only (only
``put_object`` — no read/list/delete). The bucket is **NOT** versioned: write-once-per-name
immutability comes from the locked retention policy + unique object names, not versioning
(see ``put_object``).

**Where the write-only guarantee actually lives: IAM, not this class.** The Python method
surface is a *secondary consistency guard*. The load-bearing boundary is the
``roles/storage.objectCreator``-ONLY binding on the ambient identity: it grants
``storage.objects.create`` and nothing else, so read/list/delete API calls are rejected
server-side (403). An in-process attacker could ignore this class entirely and mint an
equivalent client from the same ambient token — only IAM stops them from reading or deleting
evidence. That ``objectCreator``-only binding is provisioned in Terraform (out of 1H scope)
and MUST be verified out-of-band; if it ever grants read/delete, the write-only property
collapses with no signal in this code.

**Keyless by construction.** The production client is built via ``GCSWormBackend.keyless()``,
which uses ambient Application Default Credentials (Workload Identity Federation on Cloud
Run) — there is **no key-file parameter anywhere**, so there is no downloadable key to steal.
``google.cloud.storage`` is imported lazily inside that factory only, so this module imports
(and unit-tests run against an injected fake client) without the library installed.

The backend makes **no WORM/immutability claim** — immutability is a platform property
(bucket-lock + retention), configured by ops and verified out-of-band. This class only
deposits and reports a factual Receipt.
"""
from __future__ import annotations

from datetime import datetime

from core.evidence._util import to_iso
from core.evidence.hashing import sha256_bytes
from core.storage.base import Receipt, StorageBackend


class GCSWormBackend(StorageBackend):
    def __init__(self, bucket: str, *, client):
        """``client`` is a google.cloud.storage.Client-like object (dependency-injected).
        Production callers should use :meth:`keyless`; tests inject an in-memory fake."""
        self._bucket = bucket
        self._client = client

    @classmethod
    def keyless(cls, bucket: str) -> "GCSWormBackend":
        """Build a backend using ambient (Workload Identity / ADC) credentials — no key file.

        ``storage.Client()`` with no arguments resolves credentials from the environment
        (WIF/ADC). There is intentionally no way to pass a credentials/key path here.
        """
        from google.cloud import storage  # lazy: real dependency only for production use

        return cls(bucket, client=storage.Client())

    def put_object(
        self,
        name: str,
        data: bytes,
        *,
        stored_when: datetime,
        content_type: str = "application/json",
    ) -> Receipt:
        blob = self._client.bucket(self._bucket).blob(name)
        # Write-once-per-name. The WORM guarantee is the LOCKED RETENTION POLICY plus unique
        # object names (evidence uses UUIDs; registry revisions must use unique,
        # sequence-suffixed names). Under a locked, NON-versioned bucket, overwriting an
        # existing not-yet-expired name fails server-side (403 retentionPolicyNotMet) — the
        # strong "a name never points to different content" property. Do NOT enable bucket
        # versioning (it would let the live object at a key be replaced) and do NOT add an
        # if_generation_match precondition.
        blob.upload_from_string(data, content_type=content_type)
        generation = getattr(blob, "generation", None)
        return Receipt(
            backend="gcs",
            uri=f"gs://{self._bucket}/{name}",
            generation=str(generation) if generation is not None else None,
            sha256=sha256_bytes(data),
            stored_at=to_iso(stored_when),
        )
