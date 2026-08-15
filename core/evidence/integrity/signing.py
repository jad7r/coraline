"""
Ed25519 detached signing/verification for the evidence subsystem.

PyNaCl (libsodium) only. This is deliberately separate from ``crypto.py`` — that module
does X25519 *encryption*; this one does Ed25519 *signatures*, used to seal evidence
manifests (see ``core.evidence.seal``).

Verification FAILS CLOSED: ``verify()`` returns False on any problem — bad signature,
wrong key, malformed input — and never raises to its caller. Setup errors (e.g. a
malformed key being decoded) raise ``SigningError``; a verification *result* is always a
bool.

No network. No AI. No presentation dependencies.
"""
from __future__ import annotations

import hashlib
from typing import Tuple

import nacl.encoding
import nacl.signing

SIGNATURE_BYTES = 64  # Ed25519 detached signature length


class SigningError(Exception):
    """Key handling / setup error (distinct from a verification failure)."""


def generate_signing_keypair() -> Tuple[nacl.signing.SigningKey, nacl.signing.VerifyKey]:
    """Generate an Ed25519 signing keypair. The signing key must never be logged."""
    sk = nacl.signing.SigningKey.generate()
    return sk, sk.verify_key


def sign(message: bytes, signing_key: nacl.signing.SigningKey) -> bytes:
    """Return a 64-byte detached Ed25519 signature over ``message``."""
    try:
        return signing_key.sign(message).signature
    except Exception as e:  # pragma: no cover - defensive
        raise SigningError(f"Failed to sign: {e}") from e


def verify(message: bytes, signature: bytes, verify_key: nacl.signing.VerifyKey) -> bool:
    """Verify a detached signature. Fail-closed: returns False on ANY problem."""
    try:
        verify_key.verify(message, signature)
        return True
    except Exception:
        return False


def encode_verify_key(verify_key: nacl.signing.VerifyKey) -> str:
    """Base64 the public verify key for storage/sharing."""
    return verify_key.encode(encoder=nacl.encoding.Base64Encoder).decode("ascii")


def decode_verify_key(encoded: str) -> nacl.signing.VerifyKey:
    try:
        return nacl.signing.VerifyKey(
            encoded.encode("ascii"), encoder=nacl.encoding.Base64Encoder
        )
    except Exception as e:
        raise SigningError(f"Failed to decode verify key: {e}") from e


def encode_signing_key(signing_key: nacl.signing.SigningKey) -> bytes:
    """Raw 32-byte seed. Store only in a secure keystore; never log or transmit."""
    return bytes(signing_key)


def decode_signing_key(raw: bytes) -> nacl.signing.SigningKey:
    try:
        return nacl.signing.SigningKey(raw)
    except Exception as e:
        raise SigningError(f"Failed to decode signing key: {e}") from e


def key_fingerprint(verify_key: nacl.signing.VerifyKey) -> str:
    """Stable ``SHA256:<hex>`` fingerprint of a verify key, for signer/key identity."""
    return "SHA256:" + hashlib.sha256(bytes(verify_key)).hexdigest()
