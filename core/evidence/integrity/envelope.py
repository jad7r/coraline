"""
Envelope encryption for multi-recipient content.

Implements the envelope encryption pattern:
1. Generate a random DEK (Data Encryption Key)
2. Encrypt content with the DEK
3. Encrypt the DEK to each recipient's public key
4. Package everything into a JSON envelope

This allows multiple users to decrypt the same content without sharing keys.
"""

import json
import base64
from typing import Dict, List
from dataclasses import dataclass
import nacl.public

from core.evidence.integrity.crypto import (
    generate_dek,
    encrypt_content,
    decrypt_content,
    seal_dek,
    unseal_dek,
    decode_public_key,
    CryptoError
)


ENVELOPE_VERSION = "1"


class EnvelopeError(Exception):
    """Base exception for envelope operations."""
    pass


@dataclass
class Envelope:
    """
    Encrypted content envelope with per-recipient DEKs.

    Attributes:
        version: Envelope format version
        ciphertext: Encrypted content (base64)
        encrypted_deks: Map of user_id -> encrypted DEK (base64)
    """
    version: str
    ciphertext: str
    encrypted_deks: Dict[str, str]

    def to_json(self) -> str:
        """Serialize envelope to JSON string."""
        return json.dumps({
            "version": self.version,
            "ciphertext": self.ciphertext,
            "encrypted_deks": self.encrypted_deks
        }, indent=2)

    @staticmethod
    def from_json(json_str: str) -> 'Envelope':
        """
        Deserialize envelope from JSON string.

        Args:
            json_str: JSON-encoded envelope

        Returns:
            Envelope object

        Raises:
            EnvelopeError: If JSON is invalid or missing required fields
        """
        try:
            data = json.loads(json_str)

            if "version" not in data:
                raise EnvelopeError("Missing 'version' field")
            if "ciphertext" not in data:
                raise EnvelopeError("Missing 'ciphertext' field")
            if "encrypted_deks" not in data:
                raise EnvelopeError("Missing 'encrypted_deks' field")

            if not isinstance(data["encrypted_deks"], dict):
                raise EnvelopeError("'encrypted_deks' must be a dictionary")

            return Envelope(
                version=data["version"],
                ciphertext=data["ciphertext"],
                encrypted_deks=data["encrypted_deks"]
            )
        except json.JSONDecodeError as e:
            raise EnvelopeError(f"Invalid JSON: {e}") from e
        except EnvelopeError:
            raise
        except Exception as e:
            raise EnvelopeError(f"Failed to parse envelope: {e}") from e


@dataclass
class Recipient:
    """
    Recipient for envelope encryption.

    Attributes:
        user_id: Unique user identifier
        public_key: User's public key (base64 encoded string or PublicKey object)
    """
    user_id: str
    public_key: str

    def get_public_key_obj(self) -> nacl.public.PublicKey:
        """
        Get PublicKey object from base64 string.

        Returns:
            PublicKey object

        Raises:
            EnvelopeError: If public key is invalid
        """
        try:
            return decode_public_key(self.public_key)
        except CryptoError as e:
            raise EnvelopeError(f"Invalid public key for {self.user_id}: {e}") from e


def create_envelope(plaintext: bytes, recipients: List[Recipient]) -> Envelope:
    """
    Create an encrypted envelope for multiple recipients.

    Generates a random DEK, encrypts the content, then encrypts the DEK
    to each recipient's public key.

    Args:
        plaintext: Content to encrypt
        recipients: List of recipients with their public keys

    Returns:
        Encrypted envelope

    Raises:
        EnvelopeError: If encryption fails or no recipients provided
    """
    if not recipients:
        raise EnvelopeError("At least one recipient is required")

    if not plaintext:
        raise EnvelopeError("Plaintext cannot be empty")

    try:
        # Generate a random DEK
        dek = generate_dek()

        # Encrypt content with DEK
        ciphertext_bytes = encrypt_content(plaintext, dek)

        # Encrypt DEK for each recipient
        encrypted_deks = {}
        for recipient in recipients:
            if not recipient.user_id or not recipient.user_id.strip():
                raise EnvelopeError("Recipient user_id cannot be empty")

            # Get recipient's public key
            public_key = recipient.get_public_key_obj()

            # Seal DEK to recipient's public key
            sealed_dek = seal_dek(dek, public_key)

            # Store as base64
            encrypted_deks[recipient.user_id] = base64.b64encode(sealed_dek).decode('ascii')

        # Create envelope with base64-encoded ciphertext
        return Envelope(
            version=ENVELOPE_VERSION,
            ciphertext=base64.b64encode(ciphertext_bytes).decode('ascii'),
            encrypted_deks=encrypted_deks
        )

    except CryptoError as e:
        raise EnvelopeError(f"Encryption failed: {e}") from e
    except EnvelopeError:
        raise
    except Exception as e:
        raise EnvelopeError(f"Failed to create envelope: {e}") from e


def open_envelope(
    envelope: Envelope,
    user_id: str,
    private_key: nacl.public.PrivateKey
) -> bytes:
    """
    Decrypt an envelope's content using the current user's private key.

    Retrieves the encrypted DEK for the user, unseals it with their private key,
    then decrypts the content.

    Args:
        envelope: Encrypted envelope
        user_id: Current user's ID
        private_key: Current user's private key

    Returns:
        Decrypted plaintext

    Raises:
        EnvelopeError: If decryption fails or user not authorized
    """
    if not user_id or not user_id.strip():
        raise EnvelopeError("user_id cannot be empty")

    # Check if user is a recipient
    if user_id not in envelope.encrypted_deks:
        raise EnvelopeError(f"User {user_id} is not authorized to decrypt this content")

    try:
        # Get user's encrypted DEK
        encrypted_dek_b64 = envelope.encrypted_deks[user_id]
        encrypted_dek = base64.b64decode(encrypted_dek_b64)

        # Unseal DEK using private key
        dek = unseal_dek(encrypted_dek, private_key)

        # Decrypt content using DEK
        ciphertext = base64.b64decode(envelope.ciphertext)
        plaintext = decrypt_content(ciphertext, dek)

        return plaintext

    except CryptoError as e:
        raise EnvelopeError(f"Decryption failed: {e}") from e
    except Exception as e:
        raise EnvelopeError(f"Failed to open envelope: {e}") from e
