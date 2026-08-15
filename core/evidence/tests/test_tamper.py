"""Tamper-detection tests: manifest hash sensitivity and file re-hash mismatch."""
import dataclasses
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.evidence.hashing import sha256_file
from core.evidence.manifest import build_evidence_item, build_manifest

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)


def _mkfile(d, name, data):
    p = Path(d) / name
    p.write_bytes(data)
    return p


class TestTamper(unittest.TestCase):
    def test_manifest_hash_changes_on_item_edit(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"hello")
            m = build_manifest("i", [p], "alice", FIXED)
            before = m.manifest_hash()
            # Falsify a recorded size — the classic "swap the evidence" tamper.
            m.items[0] = dataclasses.replace(m.items[0], size=m.items[0].size + 1)
            self.assertNotEqual(m.manifest_hash(), before)

    def test_manifest_hash_changes_on_sha256_edit(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"hello")
            m = build_manifest("i", [p], "alice", FIXED)
            before = m.manifest_hash()
            m.items[0] = dataclasses.replace(m.items[0], sha256="0" * 64)
            self.assertNotEqual(m.manifest_hash(), before)

    def test_manifest_hash_changes_on_custody_edit(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"hello")
            m = build_manifest("i", [p], "alice", FIXED)
            before = m.manifest_hash()
            m.chain.events[0] = dataclasses.replace(m.chain.events[0], collector="mallory")
            self.assertNotEqual(m.manifest_hash(), before)

    def test_file_tamper_detected_by_rehash(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"original")
            item = build_evidence_item(p, collected_when=FIXED)
            p.write_bytes(b"tampered!")  # modify the file on disk
            self.assertNotEqual(sha256_file(p), item.sha256)

    def test_untampered_manifest_hash_is_stable(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"hello")
            m = build_manifest("i", [p], "alice", FIXED)
            self.assertEqual(m.manifest_hash(), m.manifest_hash())


if __name__ == "__main__":
    unittest.main()
