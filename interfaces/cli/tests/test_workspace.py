"""Tests for the incident workspace domain layer (wired to the real core)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from interfaces.cli.workspace import (
    IncidentWorkspace,
    WorkspaceError,
    verify_audit,
)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path / "incidents"


@pytest.fixture
def evidence_file(tmp_path: Path) -> Path:
    p = tmp_path / "alert.log"
    p.write_text("10.0.0.5 -> 185.220.101.4  4521 bytes exfil\n", encoding="utf-8")
    return p


def _declare(home: Path) -> IncidentWorkspace:
    return IncidentWorkspace.declare(
        home, title="DB Exfiltration Alert", severity="SEV1", actor="alice@example.com"
    )


# ---- declare ----------------------------------------------------------------- #

def test_declare_creates_signed_manifest_and_audit(home: Path):
    ws = _declare(home)
    assert ws.incident_id.startswith("INC-")
    assert ws.state["status"] == "DECLARED"
    assert ws.state["severity"] == "SEV1"
    # signed manifest + signer + key seed on disk
    assert ws._manifest_path.exists()
    assert ws._sig_path.exists()
    assert ws._signer_path.exists()
    assert ws._key_path.exists()
    # declared incident is the active one
    assert IncidentWorkspace.current_id(home) == ws.incident_id
    # audit seeded with exactly the declare event, and it verifies
    entries = ws.audit_entries()
    assert [e.action for e in entries] == ["incident-declared"]
    assert ws.verify()["audit_chain"] is True


def test_declare_rejects_bad_severity(home: Path):
    with pytest.raises(WorkspaceError):
        IncidentWorkspace.declare(home, title="x", severity="SEV9", actor="a")


def test_declare_rejects_empty_title(home: Path):
    with pytest.raises(WorkspaceError):
        IncidentWorkspace.declare(home, title="   ", severity="SEV1", actor="a")


def test_signing_key_is_chmod_600(home: Path):
    ws = _declare(home)
    mode = ws._key_path.stat().st_mode & 0o777
    assert mode == 0o600


# ---- evidence ---------------------------------------------------------------- #

def test_add_evidence_hashes_signs_and_advances(home: Path, evidence_file: Path):
    ws = _declare(home)
    res = ws.add_evidence(str(evidence_file), note="SIEM alert", actor="alice@example.com")
    assert len(res["sha256"]) == 64
    assert res["evidence_count"] == 1
    # deposited copy exists under the write-only store, named by hash
    assert res["receipt"].backend == "local"
    assert res["receipt"].sha256 == res["sha256"]
    # lifecycle advanced on first evidence
    assert ws.state["status"] == "INVESTIGATING"
    # full integrity holds
    v = ws.verify()
    assert v["manifest_signature"] is True
    assert v["custody_chain"] is True
    assert v["audit_chain"] is True


def test_add_missing_file_raises(home: Path):
    ws = _declare(home)
    with pytest.raises(WorkspaceError):
        ws.add_evidence("/no/such/file.bin", note="", actor="a")


def test_reload_preserves_signed_state(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    reloaded = IncidentWorkspace.load(home, ws.incident_id)
    v = reloaded.verify()
    assert v["manifest_signature"] and v["custody_chain"] and v["audit_chain"]
    assert reloaded.state["evidence_count"] == 1


# ---- tamper detection -------------------------------------------------------- #

def test_tampering_audit_log_is_detected(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    # corrupt the first audit entry's actor
    lines = ws._audit_path.read_text(encoding="utf-8").splitlines()
    d = json.loads(lines[0])
    d["actor"] = "mallory@evil.tld"
    lines[0] = json.dumps(d, sort_keys=True)
    ws._audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    v = ws.verify()
    assert v["audit_chain"] is False
    assert v["audit_bad_seq"] == 2  # break surfaces at the following entry


def test_tampering_manifest_breaks_signature(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    # mutate the sealed manifest bytes
    text = ws._manifest_path.read_text(encoding="utf-8")
    ws._manifest_path.write_text(text.replace("SIEM", "XXXX") if "SIEM" in text
                                 else text[:-1], encoding="utf-8")
    assert ws.verify()["manifest_signature"] is False


def test_verify_audit_helper_on_clean_chain(home: Path):
    ws = _declare(home)
    ok, bad = verify_audit(ws.audit_entries())
    assert ok and bad is None


# ---- gates + report ---------------------------------------------------------- #

def test_gates_progress_from_declare_to_report(home: Path, evidence_file: Path):
    ws = _declare(home)
    keys = {g.key: g.passed for g in ws.gates()}
    assert keys["metadata"] and not keys["evidence"] and not keys["report"]

    ws.add_evidence(str(evidence_file), note="n", actor="a")
    keys = {g.key: g.passed for g in ws.gates()}
    assert keys["evidence"] and keys["custody"] and keys["signature"] and keys["audit"]
    assert not keys["report"]

    ws.generate_report(actor="a")
    keys = {g.key: g.passed for g in ws.gates()}
    assert all(keys.values())
    assert ws.state["status"] == "RESOLVED"


def test_report_contains_integrity_attestation(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="exfil capture", actor="a")
    md = ws.generate_report(actor="a")
    assert "Post-Incident Report" in md
    assert "Manifest signature: **VALID**" in md
    assert "Chain of custody: **INTACT**" in md
    assert ws.report_path.exists()


def test_report_with_no_evidence_flags_unmet_gates(home: Path):
    ws = _declare(home)
    md = ws.generate_report(actor="a")
    assert "UNMET gates" in md
    # status should NOT advance to RESOLVED when gates are unmet
    assert ws.state["status"] == "DECLARED"


def test_simulate_tamper_then_repair_roundtrip(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    assert ws.verify()["audit_chain"] is True

    assert ws.simulate_tamper() is True
    v = ws.verify()
    assert v["audit_chain"] is False and v["audit_bad_seq"] == 2
    # tamper must NOT touch the manifest signature (granular detection)
    assert v["manifest_signature"] is True

    assert ws.repair_audit() is True
    assert ws.verify()["audit_chain"] is True
    # repairing twice is a no-op
    assert ws.repair_audit() is False


def test_close_incident_generates_pir_and_locks(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    assert ws.is_closed is False

    ws.close_incident(actor="a")
    assert ws.state["status"] == "CLOSED"
    assert ws.is_closed is True
    assert ws.report_path.exists()               # final PIR generated
    actions = [e.action for e in ws.audit_entries()]
    assert actions[-1] == "incident-closed"
    assert "report-generated" in actions
    # signature still valid after closure
    assert ws.verify()["manifest_signature"] is True

    with pytest.raises(WorkspaceError, match="evidence intake is locked"):
        ws.add_evidence(str(evidence_file), note="late evidence", actor="a")

    with pytest.raises(WorkspaceError, match="already closed"):
        ws.close_incident(actor="a")


def test_list_incidents(home: Path):
    a = _declare(home)
    b = IncidentWorkspace.declare(home, title="second", severity="SEV3", actor="a")
    ids = IncidentWorkspace.list_incidents(home)
    assert a.incident_id in ids and b.incident_id in ids
    # most recent declare is the active one
    assert IncidentWorkspace.current_id(home) == b.incident_id
