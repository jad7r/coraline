"""
Trusted signer registry.

Turns "this seal has a valid signature" into "this seal was made by a *trusted* signer".
A seal (see ``core.evidence.seal``) proves only that the holder of some key signed a
manifest hash; it says nothing about whether that key is one Coreline trusts. This registry
supplies that missing trust decision, locally and offline.

A registry maps an Ed25519 key fingerprint to a signer entry (identity, base64 verify
key, fingerprint, status, created_at, optional revoked_at). Verification looks the seal's
key up in the registry and returns one of:

    TRUSTED   — fingerprint present, status trusted, entry self-consistent, signature ok
    REVOKED   — fingerprint present but the key has been revoked
    UNKNOWN   — fingerprint not in the registry
    UNTRUSTED — malformed seal, inconsistent/tampered entry, or bad signature

Everything FAILS CLOSED: any structural, decoding, consistency, or signature problem
yields a non-TRUSTED result (or, for a malformed registry file, a RegistryError that the
file-level verify helper converts into UNTRUSTED). Deterministic JSON; no network; no
presentation dependencies. This module is part of the crypto-bound layer (it imports the
signing subsystem) and is intentionally NOT re-exported from ``core.evidence.__init__``.

Out of scope (by design): private key storage, key rotation beyond status/revocation,
WORM storage, audit logging.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import nacl.signing

from core.evidence._util import canonical_json, to_iso
from core.evidence.hashing import sha256_bytes
from core.evidence.integrity import signing
from core.evidence.manifest import EvidenceManifest
from core.evidence.seal import (
    SUBJECT_MANIFEST,
    SUBJECT_REGISTRY,
    load_seal,
    seal_content,
    verify_seal,
)

REGISTRY_VERSION = "1"

STATUS_TRUSTED = "trusted"
STATUS_REVOKED = "revoked"
_VALID_STATUSES = {STATUS_TRUSTED, STATUS_REVOKED}


class RegistryError(Exception):
    """Registry is malformed or an operation is invalid (fail-closed at load time)."""


def _is_valid_sequence(value: Any) -> bool:
    """A sequence/floor must be a non-negative int (and not a bool — ``bool`` ⊂ ``int``)."""
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


class Outcome(str, Enum):
    TRUSTED = "trusted"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class VerificationResult:
    outcome: Outcome
    signer: Optional[str]
    reason: str

    @property
    def trusted(self) -> bool:
        return self.outcome is Outcome.TRUSTED


@dataclass(frozen=True)
class SignerEntry:
    signer: str
    verify_key: str          # base64 Ed25519 public verify key
    key_fingerprint: str     # "SHA256:<hex>" — the registry index / claim
    status: str              # "trusted" | "revoked"
    created_at: str          # ISO-8601 UTC
    revoked_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Any) -> "SignerEntry":
        """Strict structural validation. Raises RegistryError on any malformation.

        Note: this validates *structure* (fields, types, status, decodable key). It does
        NOT enforce fingerprint == hash(verify_key); that semantic check is done at
        verification time so a tampered entry surfaces as UNTRUSTED there.
        """
        if not isinstance(d, dict):
            raise RegistryError("signer entry must be an object")
        try:
            signer = d["signer"]
            verify_key = d["verify_key"]
            key_fingerprint = d["key_fingerprint"]
            status = d["status"]
            created_at = d["created_at"]
        except KeyError as e:
            raise RegistryError(f"signer entry missing field: {e}") from e
        revoked_at = d.get("revoked_at")

        for name, value in (("signer", signer), ("verify_key", verify_key),
                            ("key_fingerprint", key_fingerprint),
                            ("status", status), ("created_at", created_at)):
            if not isinstance(value, str) or not value:
                raise RegistryError(f"signer entry field '{name}' must be a non-empty string")
        if status not in _VALID_STATUSES:
            raise RegistryError(f"invalid signer status: {status!r}")
        if revoked_at is not None and not isinstance(revoked_at, str):
            raise RegistryError("revoked_at must be a string or null")
        if status == STATUS_REVOKED and not revoked_at:
            raise RegistryError("revoked entry must include revoked_at")
        try:
            signing.decode_verify_key(verify_key)
        except Exception as e:
            raise RegistryError(f"undecodable verify_key: {e}") from e

        return cls(
            signer=signer,
            verify_key=verify_key,
            key_fingerprint=key_fingerprint,
            status=status,
            created_at=created_at,
            revoked_at=revoked_at,
        )


class TrustedSignerRegistry:
    """A deterministic, local collection of signer entries keyed by fingerprint."""

    VERSION = REGISTRY_VERSION

    def __init__(self, version: str = REGISTRY_VERSION, sequence: int = 0):
        if not _is_valid_sequence(sequence):
            raise RegistryError("sequence must be a non-negative integer")
        self.version = version
        self.sequence = sequence
        self.entries: Dict[str, SignerEntry] = {}

    # -- monotonic sequence (anti-rollback, Phase 1G2) ---------------------- #
    def bump(self, sequence: int) -> None:
        """Advance the monotonic sequence to a strictly-greater value.

        The sequence is part of the registry's canonical form (``to_dict``) and therefore
        covered by the root seal. The author calls ``bump`` once per signed revision;
        mutations (``add_signer``/``revoke``) deliberately do NOT auto-advance it. A
        verifier floor (``min_sequence``) then rejects any registry below the floor,
        defeating replay of an older validly-signed registry.
        """
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise RegistryError("sequence must be an integer")
        if sequence <= self.sequence:
            raise RegistryError(
                f"sequence must strictly increase (have {self.sequence}, got {sequence})"
            )
        self.sequence = sequence

    # -- construction ------------------------------------------------------- #
    def add_signer(
        self,
        signer: str,
        verify_key,
        *,
        created_when: datetime,
        status: str = STATUS_TRUSTED,
    ) -> SignerEntry:
        """Add a signer. ``verify_key`` may be a VerifyKey or a base64 string. The
        fingerprint is computed from the key, so API-created entries are always consistent.
        """
        if isinstance(verify_key, str):
            vk_b64 = verify_key
            vk = signing.decode_verify_key(vk_b64)
        else:
            vk = verify_key
            vk_b64 = signing.encode_verify_key(vk)
        if status not in _VALID_STATUSES:
            raise RegistryError(f"invalid status: {status!r}")
        entry = SignerEntry(
            signer=signer,
            verify_key=vk_b64,
            key_fingerprint=signing.key_fingerprint(vk),
            status=status,
            created_at=to_iso(created_when),
            revoked_at=None,
        )
        self.entries[entry.key_fingerprint] = entry
        return entry

    def revoke(self, key_fingerprint: str, revoked_when: datetime) -> SignerEntry:
        entry = self.entries.get(key_fingerprint)
        if entry is None:
            raise RegistryError("cannot revoke an unknown fingerprint")
        updated = dataclasses.replace(
            entry, status=STATUS_REVOKED, revoked_at=to_iso(revoked_when)
        )
        self.entries[key_fingerprint] = updated
        return updated

    def get(self, key_fingerprint: str) -> Optional[SignerEntry]:
        return self.entries.get(key_fingerprint)

    # -- serialization ------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "sequence": self.sequence,
            "signers": [self.entries[fp].to_dict() for fp in sorted(self.entries)],
        }

    def to_json(self, *, pretty: bool = False) -> str:
        if pretty:
            return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)
        return canonical_json(self.to_dict())

    def registry_hash(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()).encode("utf-8"))

    @classmethod
    def from_dict(cls, d: Any) -> "TrustedSignerRegistry":
        if not isinstance(d, dict):
            raise RegistryError("registry must be an object")
        signers = d.get("signers")
        if not isinstance(signers, list):
            raise RegistryError("registry 'signers' must be a list")
        # Backward-compatible: a registry without 'sequence' loads at 0 (a floor > 0 then
        # rejects it — no silent trust). Strict typing: reject non-int / bool / negative so
        # a malformed sequence surfaces at parse rather than skewing the floor comparison.
        raw_sequence = d.get("sequence", 0)
        if not _is_valid_sequence(raw_sequence):
            raise RegistryError("registry 'sequence' must be a non-negative integer")
        reg = cls(version=d.get("version") or cls.VERSION, sequence=raw_sequence)
        for item in signers:
            entry = SignerEntry.from_dict(item)
            if entry.key_fingerprint in reg.entries:
                raise RegistryError(f"duplicate fingerprint in registry: {entry.key_fingerprint}")
            reg.entries[entry.key_fingerprint] = entry
        return reg


# -- persistence ------------------------------------------------------------ #
def save_registry(registry: TrustedSignerRegistry, path) -> str:
    """Persist the canonical registry (file hash == registry_hash). Returns the hash."""
    Path(path).write_text(registry.to_json(), encoding="utf-8")
    return registry.registry_hash()


def load_registry(path, *, expected_hash: Optional[str] = None) -> TrustedSignerRegistry:
    """Load and structurally validate a registry. Raises RegistryError on any problem.

    If ``expected_hash`` is supplied, the loaded registry's hash must match it — this is
    how a caller pins a known-good registry and detects *any* on-disk tampering (even a
    semantically-consistent edit such as flipping a status).
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise RegistryError(f"cannot read registry: {e}") from e
    try:
        data = json.loads(text)
    except Exception as e:
        raise RegistryError(f"registry is not valid JSON: {e}") from e
    registry = TrustedSignerRegistry.from_dict(data)
    if expected_hash is not None and registry.registry_hash() != expected_hash:
        raise RegistryError("registry hash mismatch (registry changed since it was pinned)")
    return registry


# -- verification (fail-closed) --------------------------------------------- #
def verify_against_registry(
    manifest: EvidenceManifest,
    seal: Optional[Dict[str, Any]],
    registry: TrustedSignerRegistry,
    *,
    min_sequence: int = 0,
) -> VerificationResult:
    """Verify a sealed manifest against a trusted signer registry.

    ``min_sequence`` is the anti-rollback floor: a registry whose ``sequence`` is below
    it is rejected (fail-closed) before any trust is returned, defeating replay of an
    older registry. Default 0 preserves prior behavior (no floor). The floor is checked
    first here because this path receives the registry as an already-in-hand object (there
    is no root seal to verify), so there is no authenticity result for staleness to shadow.
    A misconfigured (non-int/negative) floor fails closed as UNTRUSTED, upholding the
    "never raises" contract.
    """
    if not _is_valid_sequence(min_sequence):
        return VerificationResult(
            Outcome.UNTRUSTED, None, f"invalid min_sequence floor: {min_sequence!r}"
        )
    if registry.sequence < min_sequence:
        return VerificationResult(
            Outcome.UNTRUSTED,
            None,
            f"registry sequence {registry.sequence} below floor {min_sequence}",
        )
    if not isinstance(seal, dict):
        return VerificationResult(Outcome.UNTRUSTED, None, "missing or malformed seal")
    payload = seal.get("payload")
    if not isinstance(payload, dict) or not isinstance(payload.get("key_fingerprint"), str):
        return VerificationResult(Outcome.UNTRUSTED, None, "seal missing key_fingerprint")

    fingerprint = payload["key_fingerprint"]
    entry = registry.get(fingerprint)
    if entry is None:
        return VerificationResult(Outcome.UNKNOWN, None, "signer not in trusted registry")
    if entry.status == STATUS_REVOKED:
        return VerificationResult(
            Outcome.REVOKED, entry.signer, f"signer key revoked at {entry.revoked_at}"
        )
    if entry.status != STATUS_TRUSTED:
        return VerificationResult(
            Outcome.UNTRUSTED, entry.signer, f"unknown signer status: {entry.status!r}"
        )

    try:
        verify_key = signing.decode_verify_key(entry.verify_key)
    except Exception:
        return VerificationResult(Outcome.UNTRUSTED, entry.signer, "registry entry key undecodable")

    # Semantic consistency: the entry's stored fingerprint must actually be this key's
    # fingerprint. Catches a tampered entry where the key was swapped but the fingerprint
    # (the lookup index) was left in place.
    if signing.key_fingerprint(verify_key) != entry.key_fingerprint:
        return VerificationResult(
            Outcome.UNTRUSTED, entry.signer, "registry entry fingerprint mismatch"
        )

    ok, reason = verify_seal(
        manifest.manifest_hash(), seal, verify_key, expected_subject=SUBJECT_MANIFEST
    )
    if ok:
        return VerificationResult(Outcome.TRUSTED, entry.signer, "ok")
    return VerificationResult(Outcome.UNTRUSTED, entry.signer, reason)


def verify_with_registry_file(
    manifest: EvidenceManifest,
    seal: Optional[Dict[str, Any]],
    path,
    *,
    expected_hash: Optional[str] = None,
) -> VerificationResult:
    """Load a registry from disk and verify — fail-closed if the registry is unavailable
    or malformed (never raises; returns UNTRUSTED)."""
    try:
        registry = load_registry(path, expected_hash=expected_hash)
    except RegistryError as e:
        return VerificationResult(Outcome.UNTRUSTED, None, f"registry unavailable: {e}")
    return verify_against_registry(manifest, seal, registry)


# -- registry root of trust (Phase 1G1) ------------------------------------- #
# The registry is anchored by a detached ROOT signature over its canonical hash, verified
# against an EXTERNALLY-pinned root verify key. The root key is a distinct role from the
# per-signer keys inside the registry. The root verify key is never read from the registry
# or the seal (that would be a self-describing, forgeable trust anchor) — the caller pins it.
def seal_registry(
    registry: TrustedSignerRegistry,
    root_signing_key: nacl.signing.SigningKey,
    *,
    signer: str,
    sealed_when: datetime,
) -> Dict[str, Any]:
    """Produce a detached root seal over a registry's canonical hash (subject=signer-registry).

    The registry file is not modified; persist the returned seal alongside it (convention:
    ``<registry>.seal.json``).
    """
    return seal_content(
        SUBJECT_REGISTRY,
        registry.registry_hash(),
        root_signing_key,
        signer=signer,
        sealed_when=sealed_when,
    )


def verify_registry_seal(
    registry: TrustedSignerRegistry,
    registry_seal: Optional[Dict[str, Any]],
    root_verify_key: nacl.signing.VerifyKey,
    *,
    min_sequence: int = 0,
) -> Tuple[bool, str]:
    """Verify a registry's root seal against the pinned root verify key. Fail-closed.

    Returns (ok, reason). Domain-separated: a manifest seal is rejected here (subject).
    ``min_sequence`` is the anti-rollback floor: even a validly root-sealed registry is
    rejected if its ``sequence`` is below the floor (defeats replay of an older signed
    registry). The seal is checked first so an authenticity failure dominates a stale one.
    A misconfigured (non-int/negative) floor fails closed, upholding the return-tuple contract.
    """
    if not _is_valid_sequence(min_sequence):
        return False, f"invalid min_sequence floor: {min_sequence!r}"
    ok, reason = verify_seal(
        registry.registry_hash(),
        registry_seal,
        root_verify_key,
        expected_subject=SUBJECT_REGISTRY,
    )
    if not ok:
        return ok, reason
    if registry.sequence < min_sequence:
        return False, f"registry sequence {registry.sequence} below floor {min_sequence}"
    return True, reason


def load_signed_registry(
    registry_path,
    seal_path,
    root_verify_key: nacl.signing.VerifyKey,
    *,
    min_sequence: int = 0,
) -> TrustedSignerRegistry:
    """Load a registry ONLY if its detached root seal verifies against the pinned root key.

    Fail-closed: raises RegistryError if the registry is unreadable/malformed, the seal is
    missing/malformed, the root seal does not verify, or (Phase 1G2) its ``sequence`` is
    below ``min_sequence``. A returned registry is root-verified (**tamper-evident**) AND
    at or above the caller-supplied anti-rollback floor — closing residual R2 when a real
    floor is passed. With the default ``min_sequence=0`` there is no rollback protection.
    """
    registry = load_registry(registry_path)  # raises RegistryError on unreadable/malformed
    try:
        registry_seal = load_seal(seal_path)
    except OSError as e:
        raise RegistryError(f"cannot read registry seal: {e}") from e
    except Exception as e:
        # Broad on purpose: any failure to load the seal is fail-closed as RegistryError.
        raise RegistryError(f"cannot load registry seal: {e}") from e
    ok, reason = verify_registry_seal(
        registry, registry_seal, root_verify_key, min_sequence=min_sequence
    )
    if not ok:
        raise RegistryError(f"registry root seal invalid: {reason}")
    return registry


def verify_sealed_manifest_with_signed_registry(
    manifest: EvidenceManifest,
    manifest_seal: Optional[Dict[str, Any]],
    registry_path,
    registry_seal_path,
    root_verify_key: nacl.signing.VerifyKey,
    *,
    min_sequence: int = 0,
) -> VerificationResult:
    """End-to-end trust: a manifest is TRUSTED only if BOTH the registry's root seal
    verifies against the pinned root key (and its ``sequence`` is at or above the
    anti-rollback floor ``min_sequence``, Phase 1G2) AND the manifest seal verifies against
    a trusted, non-revoked signer in that registry. Registry failure DOMINATES — a valid
    manifest seal against an untrusted/tampered/stale registry is UNTRUSTED. Never raises."""
    try:
        registry = load_signed_registry(
            registry_path, registry_seal_path, root_verify_key, min_sequence=min_sequence
        )
    except RegistryError as e:
        return VerificationResult(Outcome.UNTRUSTED, None, f"registry not trusted: {e}")
    # Floor already enforced inside load_signed_registry above (same, immutable registry
    # object) — do NOT re-thread min_sequence here or it becomes a confusing double-check.
    return verify_against_registry(manifest, manifest_seal, registry)
