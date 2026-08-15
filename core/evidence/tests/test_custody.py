"""Tests for the hash-linked chain of custody."""
import dataclasses
import unittest
from datetime import datetime, timezone

from core.evidence.custody import CustodyChain, verify_custody_chain

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)


class TestCustody(unittest.TestCase):
    def test_required_fields(self):
        c = CustodyChain()
        e = c.append("alice@example.com", "collected", FIXED, target="deadbeef")
        self.assertEqual(e.collector, "alice@example.com")
        self.assertEqual(e.action, "collected")
        self.assertEqual(e.timestamp, "2026-07-06T14:30:00Z")
        self.assertEqual(e.target, "deadbeef")

    def test_genesis_has_no_previous_hash(self):
        c = CustodyChain()
        e = c.append("alice", "collected", FIXED)
        self.assertIsNone(e.previous_hash)

    def test_linkage_and_verify(self):
        c = CustodyChain()
        e0 = c.append("a", "collected", FIXED)
        e1 = c.append("a", "preserved", FIXED)
        e2 = c.append("a", "sealed", FIXED)
        self.assertEqual(e1.previous_hash, e0.entry_hash())
        self.assertEqual(e2.previous_hash, e1.entry_hash())
        ok, idx = verify_custody_chain(c.events)
        self.assertTrue(ok)
        self.assertIsNone(idx)

    def test_detects_interior_tamper(self):
        c = CustodyChain()
        c.append("a", "collected", FIXED)
        c.append("a", "preserved", FIXED)
        c.append("a", "sealed", FIXED)
        # Alter the genesis event's action after the fact.
        c.events[0] = dataclasses.replace(c.events[0], action="EDITED")
        ok, idx = verify_custody_chain(c.events)
        self.assertFalse(ok)
        self.assertEqual(idx, 1)  # mismatch surfaces at the following event

    def test_entry_hash_is_deterministic(self):
        c1 = CustodyChain(); c1.append("a", "collected", FIXED)
        c2 = CustodyChain(); c2.append("a", "collected", FIXED)
        self.assertEqual(c1.events[0].entry_hash(), c2.events[0].entry_hash())


if __name__ == "__main__":
    unittest.main()
