#!/usr/bin/env python3
"""
Local enclave shim for the autonomous investigation engine.

The canonical signing/enclave module (``lib/enclave_adapter.py``) is built in
parallel (see ADR-0003). To keep this unit independently mergeable and testable
with no external dependency, this shim vendors a minimal, dependency-free
signer that conforms to the interface the orchestrator relies on:

    sign(payload: bytes) -> dict
    verify(payload: bytes, seal: dict) -> bool

The shim uses a keyed HMAC-SHA256 over the payload rather than a real
asymmetric enclave signature. It is *not* a security boundary — it exists so
the state machine can produce a deterministic, verifiable "cryptographic seal"
offline. The real adapter (Ed25519 / secure enclave) replaces it at integration
time via dependency injection.

# TODO(ADR-0003 integration): replace shim with lib.enclave_adapter
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Any, Dict


class EnclaveShim:
    """
    Minimal in-process signer used as the default ``enclave_adapter``.

    Conforms to the ``sign``/``verify`` interface expected by
    :class:`autonomous.agent_orchestrator.AutonomousIRBrain`. A random signing
    key is generated per instance unless one is supplied, which is sufficient
    for producing a self-consistent, verifiable seal within a single run.
    """

    SIGNER_IDENTITY = "CORELINE_ENCLAVE_SHIM_V1"
    ALGORITHM = "HMAC-SHA256"

    def __init__(self, signing_key: bytes | None = None) -> None:
        # A per-instance key keeps signatures self-consistent for verify()
        # while remaining clearly non-production.
        self._signing_key = signing_key or secrets.token_bytes(32)
        # A stable, non-secret identifier for the key material.
        self.key_id = hashlib.sha256(self._signing_key).hexdigest()[:16]

    def sign(self, payload: bytes) -> Dict[str, Any]:
        """
        Sign a byte payload and return a seal descriptor.

        Args:
            payload: Canonical bytes to sign (e.g. serialized manifest).

        Returns:
            A seal dict describing the signature. The ``signature`` field is an
            HMAC hex digest; ``manifest_hash`` is the SHA256 of the payload.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")

        signature = hmac.new(self._signing_key, payload, hashlib.sha256).hexdigest()
        return {
            "signed": True,
            "signer_identity": self.SIGNER_IDENTITY,
            "key_id": self.key_id,
            "algorithm": self.ALGORITHM,
            "signature": signature,
            "manifest_hash": hashlib.sha256(payload).hexdigest(),
        }

    def verify(self, payload: bytes, seal: Dict[str, Any]) -> bool:
        """
        Verify a payload against a seal produced by :meth:`sign`.

        Args:
            payload: The original signed bytes.
            seal: The seal dict returned by ``sign``.

        Returns:
            True if the signature and manifest hash match, else False.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        if not seal or not seal.get("signature"):
            return False

        expected = hmac.new(self._signing_key, payload, hashlib.sha256).hexdigest()
        signature_ok = hmac.compare_digest(expected, str(seal.get("signature", "")))
        hash_ok = hmac.compare_digest(
            hashlib.sha256(payload).hexdigest(),
            str(seal.get("manifest_hash", "")),
        )
        return signature_ok and hash_ok


__all__ = ["EnclaveShim"]
