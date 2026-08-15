"""
Tests for crypto module.
"""

import unittest
import nacl.public

from core.evidence.integrity.crypto import (
    generate_keypair,
    generate_dek,
    encrypt_content,
    decrypt_content,
    seal_dek,
    unseal_dek,
    encode_public_key,
    decode_public_key,
    encode_private_key,
    decode_private_key,
    CryptoError
)


class TestCrypto(unittest.TestCase):
    """Test cryptographic primitives."""

    def test_generate_keypair(self):
        """Test keypair generation."""
        private_key, public_key = generate_keypair()
        self.assertIsInstance(private_key, nacl.public.PrivateKey)
        self.assertIsInstance(public_key, nacl.public.PublicKey)

    def test_generate_dek(self):
        """Test DEK generation."""
        dek = generate_dek()
        self.assertEqual(len(dek), 32)  # 256 bits

    def test_encrypt_decrypt_content(self):
        """Test symmetric encryption and decryption."""
        plaintext = b"sensitive content"
        dek = generate_dek()

        # Encrypt
        ciphertext = encrypt_content(plaintext, dek)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertGreater(len(ciphertext), len(plaintext))

        # Decrypt
        decrypted = decrypt_content(ciphertext, dek)
        self.assertEqual(decrypted, plaintext)

    def test_decrypt_with_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        plaintext = b"sensitive content"
        dek1 = generate_dek()
        dek2 = generate_dek()

        ciphertext = encrypt_content(plaintext, dek1)

        with self.assertRaises(CryptoError):
            decrypt_content(ciphertext, dek2)

    def test_seal_unseal_dek(self):
        """Test DEK sealing and unsealing."""
        dek = generate_dek()
        private_key, public_key = generate_keypair()

        # Seal DEK to public key
        sealed_dek = seal_dek(dek, public_key)
        self.assertNotEqual(sealed_dek, dek)

        # Unseal with private key
        unsealed_dek = unseal_dek(sealed_dek, private_key)
        self.assertEqual(unsealed_dek, dek)

    def test_unseal_with_wrong_key_fails(self):
        """Test that unsealing with wrong key fails."""
        dek = generate_dek()
        private_key1, public_key1 = generate_keypair()
        private_key2, _ = generate_keypair()

        sealed_dek = seal_dek(dek, public_key1)

        with self.assertRaises(CryptoError):
            unseal_dek(sealed_dek, private_key2)

    def test_encode_decode_public_key(self):
        """Test public key encoding and decoding."""
        _, public_key = generate_keypair()

        encoded = encode_public_key(public_key)
        self.assertIsInstance(encoded, str)

        decoded = decode_public_key(encoded)
        self.assertEqual(bytes(decoded), bytes(public_key))

    def test_encode_decode_private_key(self):
        """Test private key encoding and decoding."""
        private_key, _ = generate_keypair()

        encoded = encode_private_key(private_key)
        self.assertIsInstance(encoded, bytes)
        self.assertEqual(len(encoded), 32)

        decoded = decode_private_key(encoded)
        self.assertEqual(bytes(decoded), bytes(private_key))

    def test_invalid_dek_size_fails(self):
        """Test that invalid DEK size raises error."""
        plaintext = b"test"
        invalid_dek = b"too short"

        with self.assertRaises(CryptoError):
            encrypt_content(plaintext, invalid_dek)

        with self.assertRaises(CryptoError):
            seal_dek(invalid_dek, nacl.public.PrivateKey.generate().public_key)


if __name__ == "__main__":
    unittest.main()
