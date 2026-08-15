"""
Write-only storage backend interface + Receipt (Phase 1H).

A ``StorageBackend`` deposits bytes into durable storage and returns a factual ``Receipt``.
Backends are **write-only by construction**: the interface exposes ONLY ``put_object`` —
no read, list, or delete — so a compromised caller can deposit artifacts but can never read
them back, enumerate them, or destroy them ("a mailbox slot").

The ``Receipt`` makes **no immutability / WORM claim**. A write-only backend cannot verify a
bucket's retention policy, so it never asserts one; immutability (where it exists) is a
platform/ops property, established at provisioning and verified out-of-band. This is the
deliberate fix for the prior design's false-WORM assurance.

Stdlib only. The evidence crypto core (``core.evidence``) is storage-agnostic and does not
import this package — storage is a separate, swappable layer (ADR-0002).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class Receipt:
    """Factual record of a single write. Purely descriptive — no immutability claim.

    Fields:
      backend    -- "local" | "gcs"
      uri        -- file://… | gs://…  (where the object was written)
      generation -- storage-assigned immutable generation id (GCS); None for local
      sha256     -- SHA-256 of the exact bytes written
      stored_at  -- ISO-8601 UTC instant of the write (caller-supplied; deterministic)
    """

    backend: str
    uri: str
    generation: Optional[str]
    sha256: str
    stored_at: str


class StorageBackend(ABC):
    """Write-only storage backend. Exposes ONLY ``put_object`` — never read/list/delete."""

    @abstractmethod
    def put_object(
        self,
        name: str,
        data: bytes,
        *,
        stored_when: datetime,
        content_type: str = "application/json",
    ) -> Receipt:
        """Write ``data`` under the object key ``name`` and return a Receipt.

        Implementations MUST NOT offer any read, list, or delete capability.
        """
        raise NotImplementedError
