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
    assert at.radio[1].options == ["Overview", "Evidence", "Observations", "Claims", "Actions", "Timeline", "Reports"]

    _nav(at, "Evidence")
    assert "Evidence" in _md(at)
    _nav(at, "Observations")
    assert "Observations" in _md(at)
    _nav(at, "Claims")
    assert "Claims" in _md(at)
    _nav(at, "Actions")
    assert "Actions" in _md(at)
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


def test_claim_create_workflow(tmp_path: Path):
    ws = _seed(tmp_path)
    obs = ws.add_observation("CloudTrail shows database access from unusual source IP", actor="alice@example.com")
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    _nav(at, "Claims")

    at.text_area[0].set_value("Production database was accessed from an unusual source IP")
    at.multiselect[0].set_value([obs.observation_id])
    at.selectbox[0].set_value("SUPPORTED")
    at.text_input[0].set_value("prod-db")
    record = next(b for b in at.button if "Record claim" in (b.label or ""))
    record.click().run()
    assert not at.exception

    reloaded = type(ws).load(ws.home, ws.incident_id)
    claim = reloaded.claims()[0]
    assert claim.observations == (obs.observation_id,)
    assert claim.status == "SUPPORTED"
    assert claim.subject == "prod-db"
    assert "Production database was accessed" in _md(at)


def test_claim_amendment_workflow(tmp_path: Path):
    ws = _seed(tmp_path)
    obs = ws.add_observation("CloudTrail shows database access", actor="alice@example.com")
    claim = ws.add_claim("Database was accessed", actor="alice@example.com",
                         observation_refs=[obs.observation_id])
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    _nav(at, "Claims")

    at.text_area[1].set_value("Database was accessed from a suspicious IP")
    at.text_input[0].set_value("Add source context")
    correct = next(b for b in at.button if "Save claim correction" in (b.label or ""))
    correct.click().run()

    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.effective_claim(claim.claim_id).current_text.endswith("suspicious IP")

    at.selectbox[1].set_value("SUPPORTED")
    at.text_area[2].set_value("Second analyst review completed")
    status = next(b for b in at.button if (b.label or "") == "Save status")
    status.click().run()

    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.effective_claim(claim.claim_id).current_status == "SUPPORTED"

    at.text_area[3].set_value("Superseded by final analysis")
    withdraw = next(b for b in at.button if "Withdraw claim" in (b.label or ""))
    withdraw.click().run()

    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.effective_claim(claim.claim_id).current_status == "WITHDRAWN"


def test_action_create_and_amendment_workflow(tmp_path: Path):
    ws = _seed(tmp_path)
    obs = ws.add_observation("EDR shows malware execution", actor="alice@example.com")
    claim = ws.add_claim("Host was compromised", actor="alice@example.com",
                         observation_refs=[obs.observation_id])
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    _nav(at, "Actions")

    at.text_input[0].set_value("host-isolation")
    at.text_area[0].set_value("Isolated compromised host")
    at.selectbox[0].set_value("INITIATED")
    at.text_input[1].set_value("host-01")
    at.multiselect[0].set_value([claim.claim_id])
    at.multiselect[1].set_value([obs.observation_id])
    at.text_area[1].set_value("Isolation command sent")
    record = next(b for b in at.button if "Record action" in (b.label or ""))
    record.click().run()
    assert not at.exception

    reloaded = type(ws).load(ws.home, ws.incident_id)
    action = reloaded.actions()[0]
    assert action.claims == (claim.claim_id,)
    assert action.observations == (obs.observation_id,)
    assert action.status == "INITIATED"

    at.text_area[2].set_value("Isolated host-01 from production network")
    at.text_input[2].set_value("Add hostname")
    correct = next(b for b in at.button if "Save action correction" in (b.label or ""))
    correct.click().run()

    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.effective_action(action.action_id).current_description.endswith("production network")

    at.selectbox[1].set_value("COMPLETED")
    at.text_area[3].set_value("EDR confirmed isolation")
    status = next(b for b in at.button if (b.label or "") == "Save action status")
    status.click().run()

    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.effective_action(action.action_id).current_status == "COMPLETED"

    at.text_area[5].set_value("Superseded by containment playbook")
    cancel = next(b for b in at.button if "Cancel action" in (b.label or ""))
    cancel.click().run()

    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.effective_action(action.action_id).current_status == "CANCELLED"


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
