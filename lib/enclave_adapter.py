"""
Asymmetric (Ed25519) signing adapter for Coreline services.

This is the "enclave adapter" the autonomous engine and the MCP server expect for signing.
It is a **thin façade** over the existing evidence crypto — it does NOT reimplement Ed25519.
All primitives come from :mod:`core.evidence.integrity.signing` (PyNaCl / libsodium), so
there is exactly one signing implementation in the codebase (ADR-0002 §5).

Responsibilities layered on top of the primitives:

- **Key custody.** The Ed25519 signing seed lives in the OS keychain via ``keyring`` (same
  mechanism as ``core.evidence.integrity.keystore`` and root ``storage.py``). It is
  generate-and-store on first use if absent; the private seed never leaves the keychain
  except transiently in memory to sign.
- **Stable payload canonicalization.** A ``dict`` payload is canonicalized with sorted keys
  and compact separators before signing, so ``sign`` and ``verify`` agree on the exact bytes
  regardless of dict ordering. ``bytes`` payloads are signed as-is.
- **Self-describing envelopes.** ``sign`` returns ``{signature, public_key, algorithm}``
  (base64 signature + base64 verify key) so a verifier needs nothing else.

``verify`` fails closed: any problem -> ``False`` (never raises), inheriting the evidence
subsystem's verification contract.
"""
from __future__ import annotations

import json
from typing import Any

import keyring

from core.evidence.integrity import signing

ALGORITHM = "Ed25519"

# Keychain coordinates for the adapter's signing key. Distinct service from the evidence
# keystore so operational signing keys and per-user evidence keys don't collide.
KEYRING_SERVICE = "coreline-enclave-adapter"
DEFAULT_KEY_ID = "default"


class EnclaveAdapterError(Exception):
    """Key custody / setup error (distinct from a verification result, which is a bool)."""


def canonicalize(payload: "bytes | dict[str, Any]") -> bytes:
    """Return the exact bytes that get signed for ``payload``.

    ``bytes`` are returned unchanged. A ``dict`` is JSON-encoded with sorted keys, compact
    separators, and ``ensure_ascii=False`` so signing is deterministic and stable across
    processes and dict insertion order.
    """
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, dict):
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    raise TypeError(f"payload must be bytes or dict, got {type(payload).__name__}")


class EnclaveAdapter:
    """Signs Coreline payloads with an Ed25519 key held in the OS keychain."""

    def __init__(
        self,
        key_id: str = DEFAULT_KEY_ID,
        *,
        service: str = KEYRING_SERVICE,
        keyring_backend: Any = keyring,
    ):
        """
        Args:
            key_id: logical name of the signing key (keychain username).
            service: keychain service namespace.
            keyring_backend: injectable keyring module/object exposing
                ``get_password``/``set_password`` — lets tests pass a fake in-memory
                keychain so no real OS keychain is touched.
        """
        if not key_id or not key_id.strip():
            raise EnclaveAdapterError("key_id cannot be empty")
        self._key_id = key_id
        self._service = service
        self._keyring = keyring_backend

    # -- key custody -------------------------------------------------------------------

    def _load_or_create_signing_key(self) -> signing.nacl.signing.SigningKey:
        """Fetch the signing seed from the keychain, generating+storing it if absent."""
        try:
            seed_hex = self._keyring.get_password(self._service, self._key_id)
        except Exception as e:  # keychain unavailable / locked
            raise EnclaveAdapterError(f"keychain read failed: {e}") from e

        if seed_hex is None:
            sk, _ = signing.generate_signing_keypair()
            seed_hex = signing.encode_signing_key(sk).hex()
            try:
                self._keyring.set_password(self._service, self._key_id, seed_hex)
            except Exception as e:
                raise EnclaveAdapterError(f"keychain write failed: {e}") from e
            return sk

        try:
            return signing.decode_signing_key(bytes.fromhex(seed_hex))
        except (ValueError, signing.SigningError) as e:
            raise EnclaveAdapterError(f"stored signing key is corrupt: {e}") from e

    def public_key(self) -> str:
        """Return the base64 Ed25519 verify (public) key, creating the key if needed."""
        sk = self._load_or_create_signing_key()
        return signing.encode_verify_key(sk.verify_key)

    def key_fingerprint(self) -> str:
        """Stable ``SHA256:<hex>`` fingerprint of the verify key (signer identity)."""
        sk = self._load_or_create_signing_key()
        return signing.key_fingerprint(sk.verify_key)

    # -- sign / verify -----------------------------------------------------------------

    def sign(self, payload: "bytes | dict[str, Any]") -> dict[str, str]:
        """Sign ``payload`` and return a self-describing envelope.

        Returns ``{"signature": <b64>, "public_key": <b64>, "algorithm": "Ed25519"}``.
        The signature is over :func:`canonicalize`\\ (payload).
        """
        message = canonicalize(payload)
        sk = self._load_or_create_signing_key()
        raw_sig = signing.sign(message, sk)
        return {
            "signature": _b64(raw_sig),
            "public_key": signing.encode_verify_key(sk.verify_key),
            "algorithm": ALGORITHM,
        }

    @staticmethod
    def verify(
        payload: "bytes | dict[str, Any]",
        signature: str,
        public_key: str,
    ) -> bool:
        """Verify a base64 ``signature`` over ``payload`` against a base64 ``public_key``.

        Fail-closed: returns ``False`` on any problem (bad signature, malformed key/sig,
        tampered payload) and never raises. Static because verification needs no private
        state — anyone holding the envelope can verify it.
        """
        try:
            message = canonicalize(payload)
            raw_sig = _unb64(signature)
            verify_key = signing.decode_verify_key(public_key)
        except Exception:
            return False
        return signing.verify(message, raw_sig, verify_key)


# -- base64 helpers (match evidence subsystem's base64 key encoding) --------------------

def _b64(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def _unb64(encoded: str) -> bytes:
    import base64

    return base64.b64decode(encoded.encode("ascii"))
