"""
Cryptographic primitives for secure enclave.

Uses PyNaCl (libsodium) exclusively for all cryptographic operations.
Provides safe-by-default encryption with authenticated encryption.
"""

from typing import Tuple
import nacl.public
import nacl.secret
import nacl.utils
from nacl.encoding import Base64Encoder


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


def generate_keypair() -> Tuple[nacl.public.PrivateKey, nacl.public.PublicKey]:
    """
    Generate a new asymmetric key pair for a user.

    Uses X25519 key exchange primitive.
    Private key must never be exported or logged.

    Returns:
        Tuple of (private_key, public_key)

    Raises:
        CryptoError: If key generation fails
    """
    try:
        private_key = nacl.public.PrivateKey.generate()
        public_key = private_key.public_key
        return private_key, public_key
    except Exception as e:
        raise CryptoError(f"Failed to generate keypair: {e}") from e


def generate_dek() -> bytes:
    """
    Generate a random Data Encryption Key (DEK) for symmetric encryption.

    Returns:
        32 bytes of cryptographically secure random data

    Raises:
        CryptoError: If random generation fails
    """
    try:
        return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    except Exception as e:
        raise CryptoError(f"Failed to generate DEK: {e}") from e


def encrypt_content(plaintext: bytes, dek: bytes) -> bytes:
    """
    Encrypt content using authenticated symmetric encryption.

    Uses NaCl SecretBox (XSalsa20 + Poly1305).
    Nonce is automatically generated and prepended to ciphertext.

    Args:
        plaintext: Content to encrypt
        dek: 32-byte Data Encryption Key

    Returns:
        Encrypted content (nonce + ciphertext + tag)

    Raises:
        CryptoError: If encryption fails
    """
    if len(dek) != nacl.secret.SecretBox.KEY_SIZE:
        raise CryptoError(f"DEK must be {nacl.secret.SecretBox.KEY_SIZE} bytes")

    try:
        box = nacl.secret.SecretBox(dek)
        # encrypt() automatically generates nonce and prepends it
        ciphertext = box.encrypt(plaintext)
        return ciphertext
    except Exception as e:
        raise CryptoError(f"Failed to encrypt content: {e}") from e


def decrypt_content(ciphertext: bytes, dek: bytes) -> bytes:
    """
    Decrypt content using authenticated symmetric decryption.

    Uses NaCl SecretBox (XSalsa20 + Poly1305).
    Automatically extracts nonce from ciphertext and verifies authentication tag.

    Args:
        ciphertext: Encrypted content (nonce + ciphertext + tag)
        dek: 32-byte Data Encryption Key

    Returns:
        Decrypted plaintext

    Raises:
        CryptoError: If decryption fails or authentication fails
    """
    if len(dek) != nacl.secret.SecretBox.KEY_SIZE:
        raise CryptoError(f"DEK must be {nacl.secret.SecretBox.KEY_SIZE} bytes")

    try:
        box = nacl.secret.SecretBox(dek)
        plaintext = box.decrypt(ciphertext)
        return plaintext
    except nacl.exceptions.CryptoError as e:
        raise CryptoError(f"Decryption failed - invalid key or corrupted data: {e}") from e
    except Exception as e:
        raise CryptoError(f"Failed to decrypt content: {e}") from e


def seal_dek(dek: bytes, recipient_public_key: nacl.public.PublicKey) -> bytes:
    """
    Encrypt a DEK to a recipient's public key using sealed box.

    Uses NaCl SealedBox (X25519 + XSalsa20-Poly1305).
    Anonymous encryption - recipient can decrypt but cannot verify sender.

    Args:
        dek: 32-byte Data Encryption Key to seal
        recipient_public_key: Recipient's public key

    Returns:
        Sealed (encrypted) DEK

    Raises:
        CryptoError: If sealing fails
    """
    if len(dek) != nacl.secret.SecretBox.KEY_SIZE:
        raise CryptoError(f"DEK must be {nacl.secret.SecretBox.KEY_SIZE} bytes")

    try:
        sealed_box = nacl.public.SealedBox(recipient_public_key)
        sealed_dek = sealed_box.encrypt(dek)
        return sealed_dek
    except Exception as e:
        raise CryptoError(f"Failed to seal DEK: {e}") from e


def unseal_dek(sealed_dek: bytes, recipient_private_key: nacl.public.PrivateKey) -> bytes:
    """
    Decrypt a sealed DEK using the recipient's private key.

    Uses NaCl SealedBox (X25519 + XSalsa20-Poly1305).

    Args:
        sealed_dek: Encrypted DEK
        recipient_private_key: Recipient's private key

    Returns:
        Decrypted DEK (32 bytes)

    Raises:
        CryptoError: If unsealing fails or authentication fails
    """
    try:
        sealed_box = nacl.public.SealedBox(recipient_private_key)
        dek = sealed_box.decrypt(sealed_dek)

        if len(dek) != nacl.secret.SecretBox.KEY_SIZE:
            raise CryptoError("Unsealed DEK has invalid size")

        return dek
    except nacl.exceptions.CryptoError as e:
        raise CryptoError(f"Unsealing failed - invalid key or corrupted data: {e}") from e
    except Exception as e:
        raise CryptoError(f"Failed to unseal DEK: {e}") from e


def encode_public_key(public_key: nacl.public.PublicKey) -> str:
    """
    Encode a public key to base64 string for export/storage.

    Args:
        public_key: Public key to encode

    Returns:
        Base64-encoded public key string
    """
    return public_key.encode(encoder=Base64Encoder).decode('ascii')


def decode_public_key(encoded: str) -> nacl.public.PublicKey:
    """
    Decode a base64 public key string.

    Args:
        encoded: Base64-encoded public key string

    Returns:
        PublicKey object

    Raises:
        CryptoError: If decoding fails
    """
    try:
        return nacl.public.PublicKey(encoded.encode('ascii'), encoder=Base64Encoder)
    except Exception as e:
        raise CryptoError(f"Failed to decode public key: {e}") from e


def encode_private_key(private_key: nacl.public.PrivateKey) -> bytes:
    """
    Encode a private key to bytes for keychain storage.

    WARNING: Private keys must be stored securely (keychain/HSM).
    Never log or transmit private keys.

    Args:
        private_key: Private key to encode

    Returns:
        Raw bytes of private key (32 bytes)
    """
    return bytes(private_key)


def decode_private_key(key_bytes: bytes) -> nacl.public.PrivateKey:
    """
    Decode private key from raw bytes.

    Args:
        key_bytes: 32 bytes of private key material

    Returns:
        PrivateKey object

    Raises:
        CryptoError: If decoding fails
    """
    if len(key_bytes) != 32:
        raise CryptoError("Private key must be exactly 32 bytes")

    try:
        return nacl.public.PrivateKey(key_bytes)
    except Exception as e:
        raise CryptoError(f"Failed to decode private key: {e}") from e
