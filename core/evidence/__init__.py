"""
core.evidence — deterministic evidence integrity layer.

Public API (stdlib only; no network, AI, crypto, or presentation dependencies):

  hashing:  sha256_bytes, sha256_file
  manifest: EvidenceItem, EvidenceManifest, build_evidence_item, build_manifest
  custody:  CustodyEvent, CustodyChain, verify_custody_chain

The cryptographic subsystem lives separately in ``core.evidence.integrity`` and is NOT
imported here, so this layer stays dependency-free.
"""
from core.evidence.custody import CustodyChain, CustodyEvent, verify_custody_chain
from core.evidence.hashing import sha256_bytes, sha256_file
from core.evidence.manifest import (
    HASH_ALGORITHM,
    MANIFEST_VERSION,
    EvidenceItem,
    EvidenceManifest,
    build_evidence_item,
    build_manifest,
)

__all__ = [
    "sha256_bytes",
    "sha256_file",
    "EvidenceItem",
    "EvidenceManifest",
    "build_evidence_item",
    "build_manifest",
    "MANIFEST_VERSION",
    "HASH_ALGORITHM",
    "CustodyEvent",
    "CustodyChain",
    "verify_custody_chain",
]
