"""Tests for LocalFileBackend (offline, stdlib) — Phase 1H Task 1. Red-first."""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.evidence._util import to_iso
from core.evidence.hashing import sha256_bytes
from core.storage.base import Receipt, StorageBackend
from core.storage.local import LocalFileBackend

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)


class TestLocalFileBackend(unittest.TestCase):
    def test_put_object_writes_exact_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            data = b'{"k":"v"}'
            LocalFileBackend(d).put_object("incidents/x/evidence.json", data, stored_when=FIXED)
            written = (Path(d) / "incidents/x/evidence.json").read_bytes()
            self.assertEqual(written, data)  # exact bytes, no trailing newline added

    def test_creates_parent_directories(self):
        with tempfile.TemporaryDirectory() as d:
            LocalFileBackend(d).put_object("a/b/c/d.json", b"x", stored_when=FIXED)
            self.assertTrue((Path(d) / "a/b/c/d.json").is_file())

    def test_receipt_fields(self):
        with tempfile.TemporaryDirectory() as d:
            data = b"evidence-bytes"
            r = LocalFileBackend(d).put_object("e.json", data, stored_when=FIXED)
            self.assertIsInstance(r, Receipt)
            self.assertEqual(r.backend, "local")
            self.assertEqual(r.sha256, sha256_bytes(data))
            self.assertIsNone(r.generation)  # local has no generation — no false claim
            self.assertEqual(r.stored_at, to_iso(FIXED))
            self.assertTrue(r.uri.startswith("file://"))
            self.assertIn("e.json", r.uri)

    def test_is_a_storage_backend(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsInstance(LocalFileBackend(d), StorageBackend)

    def test_custom_content_type_accepted(self):
        # content_type is part of the interface (for GCS); local accepts it without error.
        with tempfile.TemporaryDirectory() as d:
            r = LocalFileBackend(d).put_object(
                "e.bin", b"x", stored_when=FIXED, content_type="application/octet-stream"
            )
            self.assertIsInstance(r, Receipt)

    def test_rejects_absolute_name(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                LocalFileBackend(d).put_object("/etc/passwd", b"x", stored_when=FIXED)

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                LocalFileBackend(d).put_object("../escape.json", b"x", stored_when=FIXED)
            with self.assertRaises(ValueError):
                LocalFileBackend(d).put_object("a/../../escape.json", b"x", stored_when=FIXED)

    def test_rejects_symlink_escape(self):
        # Regression pin: a symlink inside root that points outside must not let a key
        # escape (.resolve() follows it; the out-of-root target is rejected at resolve time).
        import os
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, Path(d) / "evil")
            with self.assertRaises(ValueError):
                LocalFileBackend(d).put_object("evil/pwned.json", b"x", stored_when=FIXED)
            self.assertFalse((Path(outside) / "pwned.json").exists())


if __name__ == "__main__":
    unittest.main()
