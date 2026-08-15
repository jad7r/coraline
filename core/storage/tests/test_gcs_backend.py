"""Tests for GCSWormBackend — Phase 1H Task 2. Red-first.

Uses an in-memory fake GCS client (no real google-cloud-storage, no cloud creds), so the
suite stays Small/offline. The real keyless client path is exercised only by a CI-gated
staging smoke test (Task 4), never here.
"""
import inspect
import unittest
from datetime import datetime, timezone

from core.evidence._util import to_iso
from core.evidence.hashing import sha256_bytes
from core.storage.base import Receipt, StorageBackend
from core.storage.gcs import GCSWormBackend

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)

FORBIDDEN_METHODS = (
    "get", "get_object", "read", "download", "fetch",
    "list", "list_objects", "iter", "delete", "delete_object", "remove", "exists",
)


# -- in-memory fake mimicking google.cloud.storage generation semantics ------ #
class _FakeGCS:
    def __init__(self):
        self.objects = {}          # (bucket, name) -> list of version dicts
        self._gen = 1_000_000

    def bucket(self, name):
        return _FakeBucket(self, name)


class _FakeBucket:
    def __init__(self, gcs, name):
        self._gcs, self.name = gcs, name

    def blob(self, name):
        return _FakeBlob(self._gcs, self.name, name)


class _FakeBlob:
    def __init__(self, gcs, bucket, name):
        self._gcs, self._bucket, self.name = gcs, bucket, name
        self.generation = None

    def upload_from_string(self, data, content_type=None):
        self._gcs._gen += 1
        gen = self._gcs._gen
        self._gcs.objects.setdefault((self._bucket, self.name), []).append(
            {"data": data, "content_type": content_type, "generation": gen}
        )
        self.generation = gen  # real GCS populates blob.generation post-upload (int)


class TestGCSWormBackend(unittest.TestCase):
    def test_uploads_and_returns_receipt(self):
        fake = _FakeGCS()
        backend = GCSWormBackend("coreline-audit", client=fake)
        data = b'{"evidence":true}'
        r = backend.put_object("incidents/x/evidence.json", data, stored_when=FIXED)
        self.assertIsInstance(r, Receipt)
        self.assertEqual(r.backend, "gcs")
        self.assertEqual(r.uri, "gs://coreline-audit/incidents/x/evidence.json")
        self.assertEqual(r.sha256, sha256_bytes(data))
        self.assertEqual(r.stored_at, to_iso(FIXED))
        self.assertIsNotNone(r.generation)
        self.assertIsInstance(r.generation, str)
        # bytes actually reached the (fake) bucket
        stored = fake.objects[("coreline-audit", "incidents/x/evidence.json")][-1]
        self.assertEqual(stored["data"], data)

    def test_distinct_names_produce_distinct_objects(self):
        # The WORM property is a locked retention policy + UNIQUE object names (evidence uses
        # UUIDs; registry revisions use sequence-suffixed names) — NOT versioning. So the
        # contract we exercise is: distinct names -> independent objects, each with its own
        # generation. (Overwrite protection is a server-side retention-lock behaviour — a
        # same-name overwrite 403s on a locked non-versioned bucket — not modelled by the fake.)
        fake = _FakeGCS()
        backend = GCSWormBackend("b", client=fake)
        r1 = backend.put_object("incidents/x/ev-1.json", b"a", stored_when=FIXED)
        r2 = backend.put_object("incidents/x/ev-2.json", b"b", stored_when=FIXED)
        self.assertNotEqual(r1.uri, r2.uri)
        self.assertIsNotNone(r1.generation)
        self.assertIsNotNone(r2.generation)

    def test_content_type_passed_through(self):
        fake = _FakeGCS()
        GCSWormBackend("b", client=fake).put_object(
            "e.bin", b"x", stored_when=FIXED, content_type="application/octet-stream"
        )
        self.assertEqual(
            fake.objects[("b", "e.bin")][-1]["content_type"], "application/octet-stream"
        )

    def test_default_content_type_is_json(self):
        fake = _FakeGCS()
        GCSWormBackend("b", client=fake).put_object("e.json", b"x", stored_when=FIXED)
        self.assertEqual(fake.objects[("b", "e.json")][-1]["content_type"], "application/json")

    def test_is_a_storage_backend(self):
        self.assertIsInstance(GCSWormBackend("b", client=_FakeGCS()), StorageBackend)

    def test_write_only_by_construction(self):
        for m in FORBIDDEN_METHODS:
            self.assertFalse(hasattr(GCSWormBackend, m), f"GCSWormBackend must not expose {m!r}")

    def test_keyless_by_construction_no_key_param(self):
        # SC6: neither the constructor nor the keyless factory accepts a key/credentials path.
        banned = ("key", "keyfile", "key_file", "credentials", "credentials_path",
                  "credential", "service_account", "sa_key", "json_key", "keyfile_path")
        for fn in (GCSWormBackend.__init__, GCSWormBackend.keyless):
            params = set(inspect.signature(fn).parameters)
            for b in banned:
                self.assertNotIn(b, params, f"{fn.__name__} must not accept {b!r} (keyless only)")


if __name__ == "__main__":
    unittest.main()
