"""Write-only-by-construction + factual-receipt guarantees — Phase 1H Task 1. Red-first."""
import dataclasses
import unittest

from core.storage.base import Receipt, StorageBackend
from core.storage.local import LocalFileBackend

# A backend must expose NONE of these — a compromised caller can deposit but never
# read, enumerate, or destroy stored artifacts.
FORBIDDEN_METHODS = (
    "get", "get_object", "read", "download", "fetch",
    "list", "list_objects", "iter",
    "delete", "delete_object", "remove", "exists",
)


class TestWriteOnlyByConstruction(unittest.TestCase):
    def test_backend_exposes_only_put_object(self):
        for obj in (StorageBackend, LocalFileBackend):
            for m in FORBIDDEN_METHODS:
                self.assertFalse(hasattr(obj, m), f"{obj.__name__} must not expose {m!r}")

    def test_cannot_instantiate_abstract_backend(self):
        with self.assertRaises(TypeError):
            StorageBackend()  # put_object is abstract

    def test_put_object_contract(self):
        self.assertTrue(hasattr(StorageBackend, "put_object"))


class TestReceiptIsFactual(unittest.TestCase):
    def test_receipt_fields_are_exactly_expected(self):
        fields = {f.name for f in dataclasses.fields(Receipt)}
        self.assertEqual(fields, {"backend", "uri", "generation", "sha256", "stored_at"})

    def test_receipt_makes_no_worm_or_immutability_claim(self):
        names = " ".join(f.name for f in dataclasses.fields(Receipt)).lower()
        for banned in ("worm", "immutable", "locked", "retention", "verified", "trusted"):
            self.assertNotIn(banned, names)

    def test_receipt_is_frozen(self):
        r = Receipt(backend="local", uri="file:///x", generation=None,
                    sha256="0" * 64, stored_at="2026-07-06T14:30:00Z")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            r.backend = "gcs"


if __name__ == "__main__":
    unittest.main()
