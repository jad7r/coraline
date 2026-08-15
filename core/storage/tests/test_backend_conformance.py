"""Cross-backend conformance contract — Phase 1H Task 3.

Enforces the StorageBackend invariants (write-only by construction, factual receipt, no
WORM claim) uniformly across EVERY backend — so any future backend must also comply. A
negative-control "leaky" backend proves the checks actually catch violations (they are not
vacuous passing tests).
"""
import dataclasses
import tempfile
import unittest
from datetime import datetime, timezone

from core.evidence._util import to_iso
from core.evidence.hashing import sha256_bytes
from core.storage.base import Receipt, StorageBackend
from core.storage.gcs import GCSWormBackend
from core.storage.local import LocalFileBackend

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)

FORBIDDEN_METHODS = (
    "get", "get_object", "read", "download", "fetch",
    "list", "list_objects", "iter", "delete", "delete_object", "remove", "exists",
)
BANNED_RECEIPT_TERMS = ("worm", "immutable", "locked", "retention", "verified", "trusted")


# -- minimal in-memory GCS fake (mimics generation semantics) ---------------- #
class _FakeGCS:
    def __init__(self):
        self._gen = 1_000_000

    def bucket(self, name):
        return _FakeGCS._Bucket(self)

    class _Bucket:
        def __init__(self, gcs):
            self._gcs = gcs

        def blob(self, name):
            return _FakeGCS._Blob(self._gcs)

    class _Blob:
        def __init__(self, gcs):
            self._gcs, self.generation = gcs, None

        def upload_from_string(self, data, content_type=None):
            self._gcs._gen += 1
            self.generation = self._gcs._gen


def _exposes_only_put_object(cls) -> bool:
    """The write-only contract: a backend class exposes none of the read/list/delete surface."""
    return not any(hasattr(cls, m) for m in FORBIDDEN_METHODS)


class _make:
    """Backend factories, each yielding (label, backend) inside a temp context."""

    @staticmethod
    def local(stack):
        d = stack.enter_context(tempfile.TemporaryDirectory())
        return LocalFileBackend(d)

    @staticmethod
    def gcs(stack):
        return GCSWormBackend("coreline-audit", client=_FakeGCS())


BACKENDS = (("local", _make.local, LocalFileBackend), ("gcs", _make.gcs, GCSWormBackend))


class TestBackendConformance(unittest.TestCase):
    def test_all_backends_are_write_only_by_construction(self):
        for label, _, cls in BACKENDS:
            with self.subTest(backend=label):
                self.assertTrue(_exposes_only_put_object(cls),
                                f"{label} backend exposes a read/list/delete method")

    def test_all_backends_are_storage_backends(self):
        import contextlib
        for label, factory, _ in BACKENDS:
            with self.subTest(backend=label), contextlib.ExitStack() as stack:
                self.assertIsInstance(factory(stack), StorageBackend)

    def test_all_backends_return_a_factual_receipt(self):
        import contextlib
        data = b'{"evidence":true}'
        for label, factory, _ in BACKENDS:
            with self.subTest(backend=label), contextlib.ExitStack() as stack:
                r = factory(stack).put_object("incidents/x/e.json", data, stored_when=FIXED)
                self.assertIsInstance(r, Receipt)
                self.assertEqual({f.name for f in dataclasses.fields(r)},
                                 {"backend", "uri", "generation", "sha256", "stored_at"})
                self.assertEqual(r.backend, label)
                self.assertEqual(r.sha256, sha256_bytes(data))
                self.assertEqual(r.stored_at, to_iso(FIXED))

    def test_no_backend_makes_a_worm_claim(self):
        # No banned term appears in any Receipt field name (structural honesty).
        names = " ".join(f.name for f in dataclasses.fields(Receipt)).lower()
        for banned in BANNED_RECEIPT_TERMS:
            self.assertNotIn(banned, names)

    def test_negative_control_leaky_backend_is_rejected(self):
        # Proves the write-only check has teeth: a backend that adds delete() FAILS it.
        class _LeakyBackend(StorageBackend):
            def put_object(self, name, data, *, stored_when, content_type="application/json"):
                raise NotImplementedError

            def delete(self, name):  # a forbidden capability
                raise NotImplementedError

        self.assertFalse(_exposes_only_put_object(_LeakyBackend))


if __name__ == "__main__":
    unittest.main()
