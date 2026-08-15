"""Headless UI tests for the Streamlit web console via streamlit.testing AppTest.

These run the app script in-process (no browser/server) and assert the rendered
markdown reflects the underlying incident state — including the live-demo tamper
badge and incident closure.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def _seed(tmp_path: Path):
    """Create an incident + one evidence item and point CORELINE_HOME at it."""
    from interfaces.cli.workspace import IncidentWorkspace

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


def test_dashboard_renders_clean(tmp_path: Path):
    _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    blob = _md(at)
    assert "DB Exfiltration Alert" in blob
    assert "AUDIT CHAIN VERIFIED" in blob
    assert "Integrity gates" in blob
    # the demo controls + closure/report actions are present
    labels = [(b.label or "") for b in at.button]
    assert any("Simulate Evidence Tampering" in l for l in labels)
    assert any("Reset / Repair" in l for l in labels)
    assert any("Close incident" in l for l in labels)


def test_tampered_state_shows_broken_badge(tmp_path: Path):
    ws = _seed(tmp_path)
    ws.simulate_tamper()  # break the chain before render
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    blob = _md(at)
    assert "AUDIT CHAIN BROKEN" in blob
    assert "AUDIT CHAIN VERIFIED" not in blob


def test_repair_restores_verified_badge(tmp_path: Path):
    ws = _seed(tmp_path)
    ws.simulate_tamper()
    ws.repair_audit()
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    assert "AUDIT CHAIN VERIFIED" in _md(at)


def test_close_button_locks_intake_and_seals_pir(tmp_path: Path):
    ws = _seed(tmp_path)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception

    close = next(b for b in at.button if "Close incident" in (b.label or ""))
    close.click().run()
    assert not at.exception

    blob = _md(at)
    assert "INCIDENT CLOSED" in blob
    assert "EVIDENCE INTAKE LOCKED" in blob
    # backend reflects closure + a freshly sealed PIR
    reloaded = type(ws).load(ws.home, ws.incident_id)
    assert reloaded.is_closed
    assert reloaded.report_path.exists()
