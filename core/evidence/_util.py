"""
Shared, dependency-free helpers for the deterministic evidence layer.

Stdlib only. No network, no AI, no crypto, no presentation. These helpers exist so
timestamp formatting and JSON canonicalization are done identically everywhere, which
is what makes manifests reproducible.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def ensure_utc(dt: datetime) -> datetime:
    """Return a timezone-aware UTC datetime.

    A naive datetime is *assumed* to already be UTC (not local time) — the platform
    works in UTC end to end, and assuming UTC keeps behavior deterministic across hosts.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso(dt: datetime) -> str:
    """ISO-8601 in UTC with a trailing 'Z'. Deterministic for a given instant."""
    return ensure_utc(dt).isoformat().replace("+00:00", "Z")


def canonical_json(obj: Any) -> str:
    """Deterministic, compact JSON: sorted keys, no insignificant whitespace.

    Byte-for-byte reproducible for equal inputs — the basis for stable manifest hashes.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
