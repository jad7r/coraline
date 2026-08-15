"""
Append-only JSONL storage.

``JSONLStorage`` writes one JSON object per line and only ever appends — it mirrors the
offline, filesystem-first stance of :class:`core.storage.local.LocalFileBackend` (write
exact bytes under a path; no hidden mutation) while remaining stdlib-only.

Contract (as consumed by the revived Grafana webhook, ``archive/experimental/
grafana-webhook/main.py``)::

    storage = JSONLStorage('data/grafana_webhooks.jsonl')
    storage.append({'event_type': 'incident.created', ...})
    rows = storage.read_all()   # -> list[dict]

Design notes:

- **Append-only by construction.** The class exposes ``append`` and ``read_all`` only —
  no update/delete — so a caller can add records and read them back but never rewrite
  history in place.
- Parent directories are created on first append (the webhook passes ``data/…`` without
  guaranteeing ``data/`` exists).
- ``read_all`` tolerates a trailing partial/blank line (a crash mid-append leaves at most
  the last line torn) but does **not** silently swallow corrupt JSON on a complete line —
  that raises, because losing evidence records quietly is worse than failing loudly.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class JSONLStorage:
    """Append-only newline-delimited JSON store backed by a single file."""

    def __init__(self, path: "str | os.PathLike[str]"):
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def append(self, entry: dict[str, Any]) -> None:
        """Append one JSON object as a line. Creates parent dirs on first write.

        The record is serialized with ``ensure_ascii=False`` (so non-ASCII text round-trips
        verbatim) and no embedded newlines (``json.dumps`` escapes them), preserving the
        one-object-per-line invariant.
        """
        if not isinstance(entry, dict):
            raise TypeError(f"entry must be a dict, got {type(entry).__name__}")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def read_all(self) -> list[dict[str, Any]]:
        """Return every appended record in write order. Missing file -> ``[]``.

        A blank final line (or trailing whitespace) is ignored. Any other malformed line
        raises ``ValueError`` identifying the 1-based line number.
        """
        if not self._path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self._path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()
        for i, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped:
                # Blank line: only tolerable as the trailing line (torn write / EOF newline).
                if i == len(lines):
                    continue
                raise ValueError(f"{self._path}: unexpected blank line at line {i}")
            try:
                out.append(json.loads(stripped))
            except json.JSONDecodeError as e:
                raise ValueError(f"{self._path}: malformed JSON at line {i}: {e}") from e
        return out
