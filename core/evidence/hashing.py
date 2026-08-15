"""
Deterministic SHA-256 hashing for evidence.

Stdlib only (hashlib). No network, no crypto-library dependency. Files are streamed in
chunks so arbitrarily large evidence can be hashed without loading it all into memory.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union

_CHUNK = 1 << 20  # 1 MiB streaming read

PathLike = Union[str, Path]


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of a byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: PathLike) -> str:
    """Hex SHA-256 of a file's contents, read in streaming chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()
