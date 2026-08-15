"""
core.storage — write-only evidence storage backends (Phase 1H).

A StorageBackend deposits bytes into durable storage and returns a factual Receipt.
Backends are WRITE-ONLY by construction (only ``put_object`` — no read/list/delete).
The evidence crypto core (``core.evidence``) is storage-agnostic and does not import this
package; storage is a separate, swappable layer (ADR-0002).

  base:  StorageBackend, Receipt
  local: LocalFileBackend (offline, stdlib — NOT a WORM store)
  gcs:   GCSWormBackend (keyless, write-only; google-cloud-storage imported lazily)
"""
from core.storage.base import Receipt, StorageBackend
from core.storage.gcs import GCSWormBackend
from core.storage.local import LocalFileBackend

__all__ = ["StorageBackend", "Receipt", "LocalFileBackend", "GCSWormBackend"]
