"""Tests for the Ed25519 signing primitives (fail-closed verification)."""
import unittest

from core.evidence.integrity.signing import (
    decode_verify_key,
    encode_verify_key,
    generate_signing_keypair,
    key_fingerprint,
    sign,
    verify,
    SIGNATURE_BYTES,
)


class TestSigning(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        sk, vk = generate_signing_keypair()
        msg = b"evidence manifest hash"
        sig = sign(msg, sk)
        self.assertEqual(len(sig), SIGNATURE_BYTES)
        self.assertTrue(verify(msg, sig, vk))

    def test_verify_fails_on_modified_message(self):
        sk, vk = generate_signing_keypair()
        sig = sign(b"abc", sk)
        self.assertFalse(verify(b"abd", sig, vk))

    def test_verify_fails_with_wrong_key(self):
        sk1, _ = generate_signing_keypair()
        _, vk2 = generate_signing_keypair()
        sig = sign(b"abc", sk1)
        self.assertFalse(verify(b"abc", sig, vk2))

    def test_verify_fails_closed_on_garbage(self):
        _, vk = generate_signing_keypair()
        self.assertFalse(verify(b"abc", b"not-a-signature", vk))
        self.assertFalse(verify(b"abc", b"", vk))

    def test_verify_key_encode_roundtrip(self):
        _, vk = generate_signing_keypair()
        encoded = encode_verify_key(vk)
        self.assertEqual(encode_verify_key(decode_verify_key(encoded)), encoded)

    def test_fingerprint_format_and_stability(self):
        _, vk = generate_signing_keypair()
        fp = key_fingerprint(vk)
        self.assertTrue(fp.startswith("SHA256:"))
        self.assertEqual(len(fp), len("SHA256:") + 64)
        self.assertEqual(fp, key_fingerprint(vk))  # stable

    def test_distinct_keys_distinct_fingerprints(self):
        _, vk1 = generate_signing_keypair()
        _, vk2 = generate_signing_keypair()
        self.assertNotEqual(key_fingerprint(vk1), key_fingerprint(vk2))


if __name__ == "__main__":
    unittest.main()
