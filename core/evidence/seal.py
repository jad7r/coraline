"""
Detached content sealing (seal v2).

Binds a deterministic Coreline artifact (an evidence manifest, or a signer registry) to the
PyNaCl signing subsystem WITHOUT embedding any cryptography in the artifact. A *seal* is a
separate JSON document that references the artifact's SHA-256 hash, names *what* it signs
(``subject``, for domain separation), and carries an Ed25519 signature over the payload:

    {
      "payload": {
        "seal_version": "2",
        "subject": "evidence-manifest" | "signer-registry",
        "content_hash": "<sha256 hex of the canonical artifact>",
        "content_hash_algorithm": "sha256",
        "signature_algorithm": "ed25519",
        "signer": "<signer identity string>",
        "key_fingerprint": "SHA256:<hex of the verify key>",
        "sealed_at": "<ISO-8601 UTC>"
      },
      "signature": "<base64 Ed25519 signature over canonical_json(payload)>"
    }

The artifact itself is never modified and stays canonical deterministic JSON, so it can be
sealed by multiple parties independently. **Domain separation** via ``subject`` means a
seal produced for one artifact type cannot be replayed as a seal for another (a manifest
seal ≠ a registry seal), even though both may use the same key.

This module is the OPT-IN bridge between the dependency-free deterministic layer
(``core.evidence.manifest`` / ``core.evidence.registry``) and the crypto subsystem
(``core.evidence.integrity``); it is intentionally NOT imported by
``core.evidence.__init__`` so that layer stays stdlib-only.

Verification FAILS CLOSED. No network. No AI. No presentation dependencies.

Scope note: verification proves a seal was produced by the holder of a *given* verify key
over a *given* artifact of a *given* subject. Deciding *which* keys are trusted (key
distribution / signer identity) is out of scope for this module.
"""
from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import nacl.signing

from core.evidence._util import canonical_json, to_iso
from core.evidence.integrity import signing
from core.evidence.manifest import EvidenceManifest

SEAL_VERSION = "2"
_ACCEPTED_SEAL_VERSIONS = {SEAL_VERSION}
CONTENT_HASH_ALGORITHM = "sha256"
SIGNATURE_ALGORITHM = "ed25519"

# Seal subjects (domain separation). A seal is only valid for the subject it was made for.
SUBJECT_MANIFEST = "evidence-manifest"
SUBJECT_REGISTRY = "signer-registry"
_VALID_SUBJECTS = {SUBJECT_MANIFEST, SUBJECT_REGISTRY}

_REQUIRED_PAYLOAD_FIELDS = (
    "seal_version",
    "subject",
    "content_hash",
    "content_hash_algorithm",
    "signature_algorithm",
    "signer",
    "key_fingerprint",
    "sealed_at",
)


@dataclass(frozen=True)
class SealPayload:
    """The signed portion of a seal (everything except the signature itself)."""

    subject: str
    content_hash: str
    signer: str
    key_fingerprint: str
    sealed_at: str
    seal_version: str = SEAL_VERSION
    content_hash_algorithm: str = CONTENT_HASH_ALGORITHM
    signature_algorithm: str = SIGNATURE_ALGORITHM

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -- creation --------------------------------------------------------------- #
def seal_content(
    subject: str,
    content_hash: str,
    signing_key: nacl.signing.SigningKey,
    *,
    signer: str,
    sealed_when: datetime,
) -> Dict[str, Any]:
    """Produce a detached seal for a canonical artifact hash under a given subject."""
    if subject not in _VALID_SUBJECTS:
        raise ValueError(f"unknown seal subject: {subject!r}")
    payload = SealPayload(
        subject=subject,
        content_hash=content_hash,
        signer=signer,
        key_fingerprint=signing.key_fingerprint(signing_key.verify_key),
        sealed_at=to_iso(sealed_when),
    ).to_dict()
    sig = signing.sign(canonical_json(payload).encode("utf-8"), signing_key)
    return {"payload": payload, "signature": base64.b64encode(sig).decode("ascii")}


def seal_manifest_hash(
    manifest_hash: str,
    signing_key: nacl.signing.SigningKey,
    *,
    signer: str,
    sealed_when: datetime,
) -> Dict[str, Any]:
    """Produce a detached seal for an already-computed manifest hash."""
    return seal_content(
        SUBJECT_MANIFEST, manifest_hash, signing_key, signer=signer, sealed_when=sealed_when
    )


def seal_manifest(
    manifest: EvidenceManifest,
    signing_key: nacl.signing.SigningKey,
    *,
    signer: str,
    sealed_when: datetime,
) -> Dict[str, Any]:
    """Produce a detached seal binding this manifest's canonical hash."""
    return seal_manifest_hash(
        manifest.manifest_hash(), signing_key, signer=signer, sealed_when=sealed_when
    )


# -- verification (fail-closed) --------------------------------------------- #
def verify_seal(
    expected_content_hash: str,
    seal: Optional[Dict[str, Any]],
    verify_key: nacl.signing.VerifyKey,
    *,
    expected_subject: str,
) -> Tuple[bool, str]:
    """Verify a detached seal against an expected hash, subject, and verify key.

    Returns (ok, reason). Fails closed on any structural, subject, algorithmic, key,
    signature, or hash-binding problem. ``expected_subject`` enforces domain separation:
    a seal made for another subject is rejected even if its signature is otherwise valid.
    """
    if not isinstance(seal, dict):
        return False, "missing or malformed seal"
    payload = seal.get("payload")
    sig_b64 = seal.get("signature")
    if not isinstance(payload, dict) or not isinstance(sig_b64, str):
        return False, "seal missing payload or signature"
    for field in _REQUIRED_PAYLOAD_FIELDS:
        if field not in payload:
            return False, f"seal payload missing field: {field}"
    # The version is a signed field, but check its value explicitly so it is load-bearing
    # (defense-in-depth against a future cross-version replay) rather than merely present.
    if payload["seal_version"] not in _ACCEPTED_SEAL_VERSIONS:
        return False, f"unsupported seal version: {payload['seal_version']!r}"
    # Domain separation: reject a seal made for a different subject.
    if payload["subject"] != expected_subject:
        return False, (
            f"subject mismatch (expected {expected_subject!r}, got {payload['subject']!r})"
        )
    if payload["signature_algorithm"] != SIGNATURE_ALGORITHM:
        return False, "unsupported signature algorithm"
    if payload["content_hash_algorithm"] != CONTENT_HASH_ALGORITHM:
        return False, "unsupported content hash algorithm"
    # The seal must have been produced by the key we are verifying with.
    if payload["key_fingerprint"] != signing.key_fingerprint(verify_key):
        return False, "key fingerprint does not match verifying key"
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False, "signature is not valid base64"
    if not signing.verify(canonical_json(payload).encode("utf-8"), sig, verify_key):
        return False, "signature verification failed"
    # Only after the signature is trusted do we bind it to the actual content.
    if payload["content_hash"] != expected_content_hash:
        return False, "content hash mismatch (content changed since sealing)"
    return True, "ok"


def verify_sealed_manifest(
    manifest: EvidenceManifest,
    seal: Optional[Dict[str, Any]],
    verify_key: nacl.signing.VerifyKey,
) -> Tuple[bool, str]:
    """Verify a manifest seal against a live manifest (recomputes the manifest hash)."""
    return verify_seal(
        manifest.manifest_hash(), seal, verify_key, expected_subject=SUBJECT_MANIFEST
    )


# -- persistence ------------------------------------------------------------ #
def write_manifest(manifest: EvidenceManifest, path) -> str:
    """Persist the canonical manifest and a sidecar hash file. Returns the hash.

    The manifest is written as its exact canonical bytes (no trailing newline), so
    ``sha256_file(path)`` equals ``manifest.manifest_hash()``. A ``<path>.sha256`` sidecar
    persists the hash in readable form.
    """
    p = Path(path)
    p.write_text(manifest.to_json(), encoding="utf-8")
    manifest_hash = manifest.manifest_hash()
    Path(f"{p}.sha256").write_text(manifest_hash + "\n", encoding="utf-8")
    return manifest_hash


def write_seal(seal: Dict[str, Any], path) -> None:
    """Persist a seal as human-readable JSON (verification re-canonicalizes the payload)."""
    Path(path).write_text(json.dumps(seal, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_seal(path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
