"""Tests for lib.grafana_irm.GrafanaToCorelineSync — pure mapping, no I/O."""
from __future__ import annotations

import pytest

from lib.grafana_irm import GrafanaToCorelineSync


@pytest.fixture
def sync():
    return GrafanaToCorelineSync()


def test_incident_created_maps_to_declare(sync):
    out = sync.handle_webhook(
        {
            "event_type": "incident.created",
            "incident": {"id": "abc", "title": "Outage", "severity": "critical"},
        }
    )
    assert out["action"] == "declare_incident"
    assert out["grafana_incident_id"] == "abc"
    assert out["external_ref"] == "grafana:abc"
    assert out["fields"]["title"] == "Outage"
    assert out["fields"]["severity"] == "critical"
    assert out["fields"]["status"] == "open"


def test_acknowledged_maps_to_acknowledge(sync):
    out = sync.handle_webhook(
        {
            "event_type": "incident.acknowledged",
            "incident": {"id": "x1", "acknowledged_by": "alice"},
        }
    )
    assert out["action"] == "acknowledge_incident"
    assert out["fields"]["status"] == "acknowledged"
    assert out["fields"]["acknowledged_by"] == "alice"


def test_resolved_maps_to_resolve(sync):
    out = sync.handle_webhook(
        {
            "event_type": "incident.resolved",
            "incident": {"id": "x2", "resolution": "patched"},
        }
    )
    assert out["action"] == "resolve_incident"
    assert out["fields"]["status"] == "resolved"
    assert out["fields"]["resolution"] == "patched"


def test_note_created_maps_to_append_note(sync):
    out = sync.handle_webhook(
        {
            "event_type": "incident.note.created",
            "incident": {"id": "x3"},
            "note": {"body": "looking into it", "author": "bob"},
        }
    )
    assert out["action"] == "append_note"
    assert out["note"] == {"body": "looking into it", "author": "bob"}


def test_unknown_event_type_is_ignored_not_raised(sync):
    out = sync.handle_webhook({"event_type": "incident.frobnicated", "incident": {}})
    assert out["action"] == "ignore"
    assert out["reason"] == "unsupported_event_type"


def test_missing_event_type_is_ignored(sync):
    out = sync.handle_webhook({"incident": {"id": "z"}})
    assert out["action"] == "ignore"


def test_severity_normalization(sync):
    assert sync.normalize_severity("SEV1") == "critical"
    assert sync.normalize_severity("major") == "high"
    assert sync.normalize_severity("warning") == "medium"
    assert sync.normalize_severity("info") == "low"
    assert sync.normalize_severity("weird") == "unknown"
    assert sync.normalize_severity(None) == "unknown"


def test_determinism_same_input_same_output(sync):
    payload = {
        "event_type": "incident.created",
        "incident": {"id": "d", "title": "t", "severity": "high"},
    }
    assert sync.handle_webhook(payload) == sync.handle_webhook(payload)


def test_non_dict_payload_raises(sync):
    with pytest.raises(TypeError):
        sync.handle_webhook("not a dict")


def test_missing_incident_object_tolerated(sync):
    out = sync.handle_webhook({"event_type": "incident.created"})
    assert out["action"] == "declare_incident"
    assert out["grafana_incident_id"] is None
    assert out["external_ref"] is None
