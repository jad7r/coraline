"""Tests for detached manifest sealing/verification (fail-closed)."""
import base64
import copy
import dataclasses
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.evidence.hashing import sha256_file
from core.evidence.integrity.signing import generate_signing_keypair
from core.evidence.manifest import build_manifest
from core.evidence.seal import (
    SEAL_VERSION,
    SUBJECT_MANIFEST,
    SUBJECT_REGISTRY,
    load_seal,
    seal_manifest,
    verify_seal,
    verify_sealed_manifest,
    write_manifest,
    write_seal,
)

FIXED = datetime(2026, 7, 6, 14, 30, 0, tzinfo=timezone.utc)


def _manifest(d):
    p = Path(d) / "a.log"
    p.write_bytes(b"hello evidence")
    return build_manifest("sec-ir-2026-07-06-test", [p], "alice@example.com", FIXED)


class TestSeal(unittest.TestCase):
    def test_valid_seal(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            seal = seal_manifest(m, sk, signer="alice@example.com", sealed_when=FIXED)
            ok, reason = verify_sealed_manifest(m, seal, vk)
            self.assertTrue(ok, reason)
            payload = seal["payload"]
            self.assertEqual(payload["seal_version"], SEAL_VERSION)
            self.assertEqual(payload["seal_version"], "2")
            self.assertEqual(payload["subject"], SUBJECT_MANIFEST)
            self.assertEqual(payload["content_hash"], m.manifest_hash())
            self.assertEqual(payload["signature_algorithm"], "ed25519")
            self.assertEqual(payload["content_hash_algorithm"], "sha256")
            self.assertEqual(payload["signer"], "alice@example.com")
            self.assertTrue(payload["key_fingerprint"].startswith("SHA256:"))
            self.assertEqual(payload["sealed_at"], "2026-07-06T14:30:00Z")

    def test_wrong_seal_version_rejected(self):
        # The seal_version value must be load-bearing (defense-in-depth vs future
        # cross-version replay), rejected before signature verification.
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            seal = seal_manifest(m, sk, signer="a", sealed_when=FIXED)
            seal["payload"]["seal_version"] = "1"  # downgrade attempt
            ok, reason = verify_sealed_manifest(m, seal, vk)
            self.assertFalse(ok)
            self.assertIn("version", reason)

    def test_manifest_seal_rejected_under_registry_subject(self):
        # Domain separation: a manifest seal must NOT verify when a registry subject
        # is expected. Guards against cross-protocol seal replay (Phase 1G1 SC4).
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            seal = seal_manifest(m, sk, signer="a", sealed_when=FIXED)
            ok, reason = verify_seal(
                m.manifest_hash(), seal, vk, expected_subject=SUBJECT_REGISTRY
            )
            self.assertFalse(ok)
            self.assertIn("subject", reason)

    def test_modified_manifest_fails(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            seal = seal_manifest(m, sk, signer="a", sealed_when=FIXED)
            m.items[0] = dataclasses.replace(m.items[0], size=999)  # tamper the manifest
            ok, reason = verify_sealed_manifest(m, seal, vk)
            self.assertFalse(ok)
            self.assertIn("hash mismatch", reason)

    def test_modified_seal_payload_fails(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            seal = seal_manifest(m, sk, signer="a", sealed_when=FIXED)
            tampered = copy.deepcopy(seal)
            tampered["payload"]["sealed_at"] = "2000-01-01T00:00:00Z"  # not re-signed
            ok, reason = verify_sealed_manifest(m, tampered, vk)
            self.assertFalse(ok)
            self.assertIn("signature", reason)

    def test_modified_signature_fails(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            seal = seal_manifest(m, sk, signer="a", sealed_when=FIXED)
            tampered = copy.deepcopy(seal)
            raw = bytearray(base64.b64decode(tampered["signature"]))
            raw[0] ^= 0x01  # flip a bit
            tampered["signature"] = base64.b64encode(bytes(raw)).decode("ascii")
            ok, _ = verify_sealed_manifest(m, tampered, vk)
            self.assertFalse(ok)

    def test_wrong_key_fails(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, _ = generate_signing_keypair()
            _, other_vk = generate_signing_keypair()
            seal = seal_manifest(m, sk, signer="a", sealed_when=FIXED)
            ok, reason = verify_sealed_manifest(m, seal, other_vk)
            self.assertFalse(ok)
            self.assertIn("key fingerprint", reason)

    def test_missing_or_malformed_seal_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            _, vk = generate_signing_keypair()
            for bad in (None, {}, {"payload": {}}, {"signature": "x"},
                        "not-a-dict", {"payload": {"manifest_hash": "x"}, "signature": "y"}):
                ok, _ = verify_sealed_manifest(m, bad, vk)
                self.assertFalse(ok)

    def test_persist_manifest_hash_matches_file_hash(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            mp = Path(d) / "manifest.json"
            h = write_manifest(m, mp)
            self.assertEqual(h, m.manifest_hash())
            # Canonical bytes on disk hash to exactly the manifest hash.
            self.assertEqual(sha256_file(mp), h)
            # Sidecar persisted.
            self.assertEqual(Path(f"{mp}.sha256").read_text().strip(), h)

    def test_seal_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            m = _manifest(d)
            sk, vk = generate_signing_keypair()
            seal = seal_manifest(m, sk, signer="a", sealed_when=FIXED)
            sp = Path(d) / "manifest.seal.json"
            write_seal(seal, sp)
            loaded = load_seal(sp)
            ok, reason = verify_sealed_manifest(m, loaded, vk)
            self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
