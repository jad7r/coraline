"""Tests for lib.storage.JSONLStorage."""
from __future__ import annotations

import pytest

from lib.storage import JSONLStorage


def test_append_and_read_roundtrip(tmp_path):
    store = JSONLStorage(tmp_path / "sub" / "events.jsonl")
    store.append({"event": "a", "n": 1})
    store.append({"event": "b", "n": 2})
    rows = store.read_all()
    assert rows == [{"event": "a", "n": 1}, {"event": "b", "n": 2}]


def test_read_missing_file_returns_empty(tmp_path):
    store = JSONLStorage(tmp_path / "nope.jsonl")
    assert store.read_all() == []


def test_append_creates_parent_dirs(tmp_path):
    path = tmp_path / "deep" / "nested" / "log.jsonl"
    JSONLStorage(path).append({"x": 1})
    assert path.exists()


def test_append_only_preserves_order_across_instances(tmp_path):
    path = tmp_path / "log.jsonl"
    JSONLStorage(path).append({"i": 0})
    JSONLStorage(path).append({"i": 1})
    assert [r["i"] for r in JSONLStorage(path).read_all()] == [0, 1]


def test_non_dict_entry_rejected(tmp_path):
    store = JSONLStorage(tmp_path / "log.jsonl")
    with pytest.raises(TypeError):
        store.append(["not", "a", "dict"])


def test_non_ascii_roundtrips(tmp_path):
    store = JSONLStorage(tmp_path / "log.jsonl")
    store.append({"msg": "café — naïve"})
    assert store.read_all()[0]["msg"] == "café — naïve"


def test_trailing_blank_line_tolerated(tmp_path):
    path = tmp_path / "log.jsonl"
    store = JSONLStorage(path)
    store.append({"a": 1})
    # Simulate an extra blank trailing line.
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n")
    assert store.read_all() == [{"a": 1}]


def test_malformed_line_raises(tmp_path):
    path = tmp_path / "log.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        fh.write("{not json}\n")
    with pytest.raises(ValueError):
        JSONLStorage(path).read_all()
