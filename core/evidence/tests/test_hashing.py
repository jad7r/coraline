"""Tests for deterministic SHA-256 hashing."""
import tempfile
import unittest
from pathlib import Path

from core.evidence.hashing import sha256_bytes, sha256_file

# Canonical NIST test vectors.
SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


class TestHashing(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(sha256_bytes(b""), SHA256_EMPTY)
        self.assertEqual(sha256_bytes(b"abc"), SHA256_ABC)

    def test_file_matches_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "evidence.txt"
            p.write_bytes(b"evidence-123")
            self.assertEqual(sha256_file(p), sha256_bytes(b"evidence-123"))

    def test_large_file_streaming(self):
        # >1 MiB and not a multiple of the 1 MiB chunk size, to exercise chunking.
        data = b"x" * (3 * (1 << 20) + 7)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "big.bin"
            p.write_bytes(data)
            self.assertEqual(sha256_file(p), sha256_bytes(data))

    def test_change_changes_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f"
            p.write_bytes(b"A")
            h1 = sha256_file(p)
            p.write_bytes(b"B")
            h2 = sha256_file(p)
            self.assertNotEqual(h1, h2)

    def test_digest_is_64_hex(self):
        digest = sha256_bytes(b"anything")
        self.assertEqual(len(digest), 64)
        int(digest, 16)  # raises if not hex


if __name__ == "__main__":
    unittest.main()
