"""Tests for timestamp handling (UTC normalization, file-time capture)."""
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.evidence._util import to_iso
from core.evidence.manifest import build_evidence_item

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)


class TestTimestamps(unittest.TestCase):
    def test_utc_z_suffix(self):
        self.assertEqual(to_iso(FIXED), "2026-07-06T14:30:00Z")

    def test_naive_assumed_utc(self):
        self.assertEqual(to_iso(datetime(2026, 7, 6, 14, 30, 0)), "2026-07-06T14:30:00Z")

    def test_offset_converted_to_utc(self):
        dt = datetime(2026, 7, 6, 10, 30, 0, tzinfo=timezone(timedelta(hours=-4)))
        self.assertEqual(to_iso(dt), "2026-07-06T14:30:00Z")

    def test_collection_timestamp_is_injected(self):
        # Determinism requires the collection time be an input, not wall-clock.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f"
            p.write_bytes(b"x")
            item = build_evidence_item(p, collected_when=FIXED)
            self.assertEqual(item.collected_at, "2026-07-06T14:30:00Z")

    def test_modified_reflects_file_mtime(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f"
            p.write_bytes(b"x")
            os.utime(p, (1_000_000_000, 1_000_000_000))  # fixed epoch mtime
            item = build_evidence_item(p, collected_when=FIXED)
            expected = to_iso(datetime.fromtimestamp(1_000_000_000, tz=timezone.utc))
            self.assertEqual(item.modified, expected)


if __name__ == "__main__":
    unittest.main()
