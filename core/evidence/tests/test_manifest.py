"""Tests for evidence manifest structure, determinism, and machine-readability."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.evidence.manifest import (
    MANIFEST_VERSION,
    EvidenceManifest,
    build_evidence_item,
    build_manifest,
)

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)


def _mkfile(d, name, data):
    p = Path(d) / name
    p.write_bytes(data)
    return p


class TestManifest(unittest.TestCase):
    def test_evidence_item_required_fields(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"hello")
            item = build_evidence_item(p, collected_when=FIXED)
            self.assertEqual(item.size, 5)
            self.assertEqual(len(item.sha256), 64)
            self.assertEqual(item.collected_at, "2026-07-06T14:30:00Z")
            self.assertEqual(item.algorithm, "sha256")
            self.assertTrue(item.modified)  # mtime always available
            self.assertEqual(item.path, str(p))

    def test_manifest_structure(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"hello")
            m = build_manifest("sec-ir-2026-07-06-test", [p], "alice@example.com", FIXED)
            data = m.to_dict()
            self.assertEqual(data["version"], MANIFEST_VERSION)
            self.assertEqual(data["algorithm"], "sha256")
            self.assertEqual(data["incident_id"], "sec-ir-2026-07-06-test")
            self.assertEqual(len(data["items"]), 1)
            self.assertGreaterEqual(len(data["custody"]), 2)
            self.assertEqual(data["custody"][0]["action"], "collected")
            self.assertEqual(data["custody"][-1]["action"], "manifest-sealed")

    def test_deterministic_regardless_of_add_order(self):
        with tempfile.TemporaryDirectory() as d:
            a = _mkfile(d, "a.log", b"aaa")
            b = _mkfile(d, "b.log", b"bbb")
            m1 = EvidenceManifest("i", FIXED)
            m1.add_item(build_evidence_item(a, collected_when=FIXED))
            m1.add_item(build_evidence_item(b, collected_when=FIXED))
            m2 = EvidenceManifest("i", FIXED)
            m2.add_item(build_evidence_item(b, collected_when=FIXED))
            m2.add_item(build_evidence_item(a, collected_when=FIXED))
            self.assertEqual(m1.to_json(), m2.to_json())
            self.assertEqual(m1.manifest_hash(), m2.manifest_hash())

    def test_canonical_json_is_compact_and_sorted(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"hello")
            m = build_manifest("i", [p], "alice", FIXED)
            j = m.to_json()
            self.assertNotIn(", ", j)   # compact separators
            self.assertNotIn(": ", j)
            # keys within the top-level object are sorted
            top = json.loads(j)
            self.assertEqual(list(top.keys()), sorted(top.keys()))

    def test_json_roundtrip_is_stable(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"hello")
            m = build_manifest("i", [p], "alice", FIXED)
            j = m.to_json()
            m2 = EvidenceManifest.from_dict(json.loads(j))
            self.assertEqual(m2.to_json(), j)
            self.assertEqual(m2.manifest_hash(), m.manifest_hash())

    def test_machine_readable_valid_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = _mkfile(d, "a.log", b"hello")
            m = build_manifest("i", [p], "alice", FIXED)
            json.loads(m.to_json())          # compact parses
            json.loads(m.to_json(pretty=True))  # pretty parses


if __name__ == "__main__":
    unittest.main()
