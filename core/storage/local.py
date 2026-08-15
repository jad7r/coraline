"""
LocalFileBackend — offline, stdlib filesystem storage (Phase 1H).

Writes exact bytes under a root directory. Intended for offline operation and tests — it is
**NOT** a WORM store (the local filesystem is mutable), and its Receipt says nothing about
immutability. Object names are validated to stay within the root (no path traversal), since
the name is external input.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path, PurePosixPath

from core.evidence._util import to_iso
from core.evidence.hashing import sha256_bytes
from core.storage.base import Receipt, StorageBackend


class LocalFileBackend(StorageBackend):
    # Threat-model note: object keys use POSIX-style ("/") separators and are validated at
    # resolve time — .resolve() follows symlinks, so a symlink inside the root that points
    # outside is correctly rejected. A residual symlink-TOCTOU window remains (an attacker
    # who can swap an intermediate directory for a symlink *between* resolve and write could
    # escape). This backend therefore ASSUMES A TRUSTED LOCAL ROOT and is for offline/dev/
    # test use only; the production custody guarantee comes from the GCS WORM backend, not
    # this class. (O_NOFOLLOW hardening intentionally deferred.)
    def __init__(self, root: "str | Path"):
        self._root = Path(root).resolve()

    def _resolve(self, name: str) -> Path:
        """Map an object key to a path strictly inside the root. Rejects absolute names and
        any parent traversal (external-input hardening). POSIX path semantics."""
        if not name or name.startswith("/"):
            raise ValueError(f"object name must be a relative key: {name!r}")
        parts = PurePosixPath(name).parts
        if any(p == ".." for p in parts):
            raise ValueError(f"object name must not traverse parents: {name!r}")
        target = (self._root / Path(*parts)).resolve()  # follows symlinks
        if self._root not in target.parents:  # must be strictly under root
            raise ValueError(f"object name escapes storage root: {name!r}")
        return target

    def put_object(
        self,
        name: str,
        data: bytes,
        *,
        stored_when: datetime,
        content_type: str = "application/json",
    ) -> Receipt:
        # content_type is part of the interface (used by GCS); the local filesystem
        # backend does not record it. It is accepted for interface conformance.
        target = self._resolve(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return Receipt(
            backend="local",
            uri=target.as_uri(),
            generation=None,
            sha256=sha256_bytes(data),
            stored_at=to_iso(stored_when),
        )
