"""
Secure key storage using OS-native keychain.

Uses Python keyring for cross-platform secure storage:
- macOS: Keychain
- Linux: Secret Service API / kwallet
- Windows: Windows Credential Locker

Private keys never leave secure storage except when explicitly retrieved for use.
"""

import keyring
import nacl.public
from typing import Optional

from core.evidence.integrity.crypto import encode_private_key, decode_private_key, CryptoError


# Keyring service name for this application
KEYRING_SERVICE = "secops-secure-enclave"


class KeystoreError(Exception):
    """Base exception for keystore operations."""
    pass


def store_private_key(user_id: str, private_key: nacl.public.PrivateKey) -> None:
    """
    Store a user's private key in OS-native secure storage.

    The key is stored under service='secops-secure-enclave' with username=user_id.
    On macOS, this uses Keychain. Keys are encrypted at rest by the OS.

    Args:
        user_id: Unique identifier for the user (e.g., Okta user ID)
        private_key: User's private key to store

    Raises:
        KeystoreError: If storage fails
    """
    if not user_id or not user_id.strip():
        raise KeystoreError("user_id cannot be empty")

    try:
        # Encode private key to bytes
        key_bytes = encode_private_key(private_key)

        # Convert bytes to hex string for keyring storage
        # (keyring expects string passwords)
        key_hex = key_bytes.hex()

        # Store in OS keychain
        keyring.set_password(KEYRING_SERVICE, user_id, key_hex)

    except CryptoError as e:
        raise KeystoreError(f"Failed to encode private key: {e}") from e
    except Exception as e:
        raise KeystoreError(f"Failed to store private key in keychain: {e}") from e


def retrieve_private_key(user_id: str) -> nacl.public.PrivateKey:
    """
    Retrieve a user's private key from OS-native secure storage.

    Args:
        user_id: Unique identifier for the user

    Returns:
        User's private key

    Raises:
        KeystoreError: If retrieval fails or key not found
    """
    if not user_id or not user_id.strip():
        raise KeystoreError("user_id cannot be empty")

    try:
        # Retrieve from OS keychain
        key_hex = keyring.get_password(KEYRING_SERVICE, user_id)

        if key_hex is None:
            raise KeystoreError(f"No private key found for user: {user_id}")

        # Convert hex string back to bytes
        key_bytes = bytes.fromhex(key_hex)

        # Decode to PrivateKey object
        return decode_private_key(key_bytes)

    except ValueError as e:
        raise KeystoreError(f"Stored key has invalid format: {e}") from e
    except CryptoError as e:
        raise KeystoreError(f"Failed to decode private key: {e}") from e
    except KeystoreError:
        raise
    except Exception as e:
        raise KeystoreError(f"Failed to retrieve private key from keychain: {e}") from e


def delete_private_key(user_id: str) -> None:
    """
    Delete a user's private key from secure storage.

    This is a destructive operation and cannot be undone.
    Use with caution.

    Args:
        user_id: Unique identifier for the user

    Raises:
        KeystoreError: If deletion fails
    """
    if not user_id or not user_id.strip():
        raise KeystoreError("user_id cannot be empty")

    try:
        keyring.delete_password(KEYRING_SERVICE, user_id)
    except keyring.errors.PasswordDeleteError:
        # Key doesn't exist - this is fine
        pass
    except Exception as e:
        raise KeystoreError(f"Failed to delete private key from keychain: {e}") from e


def key_exists(user_id: str) -> bool:
    """
    Check if a private key exists for a user without retrieving it.

    Args:
        user_id: Unique identifier for the user

    Returns:
        True if key exists, False otherwise
    """
    if not user_id or not user_id.strip():
        return False

    try:
        key_hex = keyring.get_password(KEYRING_SERVICE, user_id)
        return key_hex is not None
    except Exception:
        # Fail closed - if we can't check, assume it doesn't exist
        return False
