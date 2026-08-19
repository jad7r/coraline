"""Headless UI tests for the Streamlit investigation workstation."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def _seed(tmp_path: Path):
    """Create an incident + one evidence item and point CORELINE_HOME at it."""
    from core.incident import IncidentWorkspace

    home = tmp_path / "incidents"
    ev = tmp_path / "alert.log"
    ev.write_text("exfil evidence\n", encoding="utf-8")
    os.environ["CORELINE_HOME"] = str(home)
    os.environ["CORELINE_ACTOR"] = "alice@example.com"
    ws = IncidentWorkspace.declare(home, title="DB Exfiltration Alert",
                                   severity="SEV1", actor="alice@example.com")
    ws.add_evidence(str(ev), note="SIEM alert", actor="alice@example.com")
    return ws


def _md(at) -> str:
    return " ".join(str(m.value) for m in at.markdown)


def _nav(at, target: str):
    at.radio[1].set_value(target).run()
    return at


def test_incident_loading_and_navigation(tmp_path: Path):
    _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    blob = _md(at)
    assert "DB Exfiltration Alert" in blob
    assert "Integrity verified" in blob
    assert at.radio[1].options == ["Overview", "Evidence", "Observations", "Timeline", "Reports"]

    _nav(at, "Evidence")
    assert "Evidence" in _md(at)
    _nav(at, "Observations")
    assert "Observations" in _md(at)
    _nav(at, "Timeline")
    assert "AUDIT CHAIN VERIFIED" in _md(at)


def test_security_integrity_panel_and_tamper_state(tmp_path: Path):
    ws = _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception

    security = next(b for b in at.button if "Security & Integrity" in (b.label or ""))
    security.click().run()
    blob = _md(at)
    assert "Security & Integrity" in blob
    assert "Custody" in blob or "Chain of custody" in blob
    assert any("Simulate Evidence Tampering" in (b.label or "") for b in at.button)

    ws.simulate_tamper()
    at = AppTest.from_file(APP, default_timeout=60).run()
    blob = _md(at)
    assert "Integrity issue detected" in blob


def test_repair_restores_verified_badge(tmp_path: Path):
    ws = _seed(tmp_path)
    ws.simulate_tamper()
    ws.repair_audit()
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    assert "Integrity verified" in _md(at)


def test_incident_metadata_edit_is_audited(tmp_path: Path):
    ws = _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception

    at.text_input[0].set_value("Production Database Compromise")
    at.text_area[0].set_value("Customer database access investigation.")
    at.selectbox[0].set_value("SEV2")
    save = next(b for b in at.button if "Save metadata" in (b.label or ""))
    save.click().run()
    assert not at.exception

    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.state["title"] == "Production Database Compromise"
    assert reloaded.state["severity"] == "SEV2"
    assert reloaded.state["description"] == "Customer database access investigation."
    assert reloaded.audit_entries()[-1].action == "incident-metadata-updated"


def test_evidence_view_lists_evidence(tmp_path: Path):
    _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    _nav(at, "Evidence")
    assert not at.exception
    assert "alert.log" in str(at.dataframe[0].value)


def test_observation_create_correct_retract_workflow(tmp_path: Path):
    ws = _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    _nav(at, "Observations")

    at.text_area[0].set_value("CloudTrail shows database access from unusual source IP")
    at.text_input[0].set_value("prod-db")
    record = next(b for b in at.button if "Record observation" in (b.label or ""))
    record.click().run()
    assert not at.exception

    reloaded = type(ws).load(ws.home, ws.incident_id)
    obs = reloaded.observations()[0]
    assert obs.subject == "prod-db"
    assert "CloudTrail shows database access" in _md(at)

    at.text_area[1].set_value("CloudTrail shows database access from 203.0.113.10")
    at.text_input[0].set_value("Corrected source IP")
    correct = next(b for b in at.button if "Save correction" in (b.label or ""))
    correct.click().run()

    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.effective_observation(obs.observation_id).current_text.endswith("203.0.113.10")

    at.text_area[2].set_value("Duplicate observation captured elsewhere")
    retract = next(b for b in at.button if "Retract observation" in (b.label or ""))
    retract.click().run()

    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.effective_observation(obs.observation_id).current_status == "RETRACTED"


def test_lifecycle_controls(tmp_path: Path):
    ws = _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception

    contain = next(b for b in at.button if (b.label or "") == "Contain")
    contain.click().run()
    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.state["status"] == "CONTAINED"


def test_report_close_button_locks_incident(tmp_path: Path):
    ws = _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    _nav(at, "Reports")

    close = next(b for b in at.button if "Close incident" in (b.label or ""))
    close.click().run()
    assert not at.exception

    # backend reflects closure + a freshly sealed PIR
    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.is_closed
    assert reloaded.report_path.exists()


def test_observation_validation_error_is_visible(tmp_path: Path):
    _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    _nav(at, "Observations")

    record = next(b for b in at.button if "Record observation" in (b.label or ""))
    record.click().run()
    assert at.error
    assert "observation text must not be empty" in at.error[0].value
