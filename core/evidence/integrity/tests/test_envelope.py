"""
Tests for envelope module.
"""

import unittest

from core.evidence.integrity.crypto import generate_keypair, encode_public_key
from core.evidence.integrity.envelope import (
    create_envelope,
    open_envelope,
    Envelope,
    Recipient,
    EnvelopeError
)


class TestEnvelope(unittest.TestCase):
    """Test envelope encryption."""

    def setUp(self):
        """Set up test fixtures."""
        # Generate keys for two users
        self.private_key1, self.public_key1 = generate_keypair()
        self.private_key2, self.public_key2 = generate_keypair()

        self.user1_id = "user1@example.com"
        self.user2_id = "user2@example.com"

        self.recipient1 = Recipient(
            user_id=self.user1_id,
            public_key=encode_public_key(self.public_key1)
        )
        self.recipient2 = Recipient(
            user_id=self.user2_id,
            public_key=encode_public_key(self.public_key2)
        )

    def test_create_and_open_envelope_single_recipient(self):
        """Test creating and opening envelope with one recipient."""
        plaintext = b"secret message"

        # Create envelope
        envelope = create_envelope(plaintext, [self.recipient1])

        # Verify envelope structure
        self.assertEqual(envelope.version, "1")
        self.assertIn(self.user1_id, envelope.encrypted_deks)
        self.assertEqual(len(envelope.encrypted_deks), 1)

        # Open envelope
        decrypted = open_envelope(envelope, self.user1_id, self.private_key1)
        self.assertEqual(decrypted, plaintext)

    def test_create_and_open_envelope_multiple_recipients(self):
        """Test creating and opening envelope with multiple recipients."""
        plaintext = b"secret message for multiple users"

        # Create envelope for both users
        envelope = create_envelope(plaintext, [self.recipient1, self.recipient2])

        # Verify both recipients are included
        self.assertIn(self.user1_id, envelope.encrypted_deks)
        self.assertIn(self.user2_id, envelope.encrypted_deks)
        self.assertEqual(len(envelope.encrypted_deks), 2)

        # Both users can decrypt
        decrypted1 = open_envelope(envelope, self.user1_id, self.private_key1)
        decrypted2 = open_envelope(envelope, self.user2_id, self.private_key2)

        self.assertEqual(decrypted1, plaintext)
        self.assertEqual(decrypted2, plaintext)

    def test_unauthorized_user_cannot_decrypt(self):
        """Test that unauthorized user cannot decrypt."""
        plaintext = b"secret message"

        # Create envelope for user1 only
        envelope = create_envelope(plaintext, [self.recipient1])

        # User2 should not be able to decrypt
        with self.assertRaises(EnvelopeError) as ctx:
            open_envelope(envelope, self.user2_id, self.private_key2)

        self.assertIn("not authorized", str(ctx.exception))

    def test_wrong_private_key_fails(self):
        """Test that wrong private key fails to decrypt."""
        plaintext = b"secret message"

        # Create envelope for user1
        envelope = create_envelope(plaintext, [self.recipient1])

        # Try to decrypt with wrong private key (but correct user_id)
        with self.assertRaises(EnvelopeError):
            open_envelope(envelope, self.user1_id, self.private_key2)

    def test_envelope_serialization(self):
        """Test envelope JSON serialization and deserialization."""
        plaintext = b"test data"

        # Create envelope
        envelope = create_envelope(plaintext, [self.recipient1])

        # Serialize to JSON
        json_str = envelope.to_json()
        self.assertIsInstance(json_str, str)

        # Deserialize from JSON
        envelope2 = Envelope.from_json(json_str)

        # Should be able to decrypt from deserialized envelope
        decrypted = open_envelope(envelope2, self.user1_id, self.private_key1)
        self.assertEqual(decrypted, plaintext)

    def test_empty_plaintext_fails(self):
        """Test that empty plaintext raises error."""
        with self.assertRaises(EnvelopeError):
            create_envelope(b"", [self.recipient1])

    def test_no_recipients_fails(self):
        """Test that no recipients raises error."""
        with self.assertRaises(EnvelopeError):
            create_envelope(b"test", [])

    def test_invalid_json_fails(self):
        """Test that invalid JSON raises error."""
        with self.assertRaises(EnvelopeError):
            Envelope.from_json("not valid json")

    def test_missing_fields_fails(self):
        """Test that missing required fields raises error."""
        incomplete_json = '{"version": "1"}'

        with self.assertRaises(EnvelopeError):
            Envelope.from_json(incomplete_json)


if __name__ == "__main__":
    unittest.main()
