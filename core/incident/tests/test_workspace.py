"""Tests for the incident workspace domain layer (wired to the real core)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest

from core.incident import (
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
    assert ws.state["status"] == "OPEN"
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


def test_verify_detects_missing_stored_evidence(home: Path, evidence_file: Path):
    ws = _declare(home)
    res = ws.add_evidence(str(evidence_file), note="n", actor="a")
    stored = Path(unquote(urlparse(res["receipt"].uri).path))
    stored.unlink()

    v = ws.verify()
    assert v["storage_artifacts"] is False
    assert res["receipt"].uri in v["storage_missing"]
    keys = {g.key: g.passed for g in ws.gates()}
    assert keys["storage"] is False


def test_verify_detects_stored_evidence_hash_mismatch(home: Path, evidence_file: Path):
    ws = _declare(home)
    res = ws.add_evidence(str(evidence_file), note="n", actor="a")
    stored = Path(unquote(urlparse(res["receipt"].uri).path))
    stored.write_text("changed bytes\n", encoding="utf-8")

    v = ws.verify()
    assert v["storage_artifacts"] is False
    assert res["receipt"].uri in v["storage_bad_hash"][0]


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


def test_add_observation_references_manifest_evidence_and_audits(home: Path, evidence_file: Path):
    ws = _declare(home)
    res = ws.add_evidence(str(evidence_file), note="n", actor="a")

    obs = ws.add_observation(
        text="CloudTrail shows database access from unusual source IP",
        actor="analyst@example.com",
        evidence_refs=[res["sha256"]],
        disposition="SUSPECTED",
        subject="prod-db",
    )

    assert obs.observation_id.startswith("OBS-")
    assert obs.incident_id == ws.incident_id
    assert obs.evidence == (res["sha256"],)
    assert ws.state["observation_count"] == 1
    assert ws.verify()["observations"] is True
    entry = ws.audit_entries()[-1]
    assert entry.action == "observation-created"
    assert entry.actor == "analyst@example.com"
    assert entry.detail["observation_id"] == obs.observation_id
    assert entry.detail["evidence"] == [res["sha256"]]
    assert entry.detail["text_hash"] == obs.text_hash()


def test_observation_with_no_evidence_is_allowed_and_verifiable(home: Path):
    ws = _declare(home)

    obs = ws.add_observation("Initial interview scheduled", actor="a")

    assert obs.evidence == ()
    assert ws.verify()["observations"] is True


def test_observation_rejects_nonexistent_or_path_evidence(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")

    with pytest.raises(WorkspaceError, match="evidence not found"):
        ws.add_observation("x", actor="a", evidence_refs=["0" * 64])

    with pytest.raises(WorkspaceError, match="invalid evidence reference"):
        ws.add_observation("x", actor="a", evidence_refs=[str(evidence_file)])


def test_observation_rejects_evidence_from_another_incident(home: Path, evidence_file: Path, tmp_path: Path):
    first = _declare(home)
    other_file = tmp_path / "other.log"
    other_file.write_text("other incident evidence\n", encoding="utf-8")
    second = IncidentWorkspace.declare(home, title="second", severity="SEV3", actor="a")
    other = second.add_evidence(str(other_file), note="n", actor="a")

    assert other["sha256"] not in first.evidence_shas()
    with pytest.raises(WorkspaceError, match="evidence not found"):
        first.add_observation("Cross-case reference", actor="a", evidence_refs=[other["sha256"]])


def test_observation_rejects_malformed_input(home: Path):
    ws = _declare(home)

    with pytest.raises(WorkspaceError, match="text must not be empty"):
        ws.add_observation("   ", actor="a")
    with pytest.raises(WorkspaceError, match="invalid observation disposition"):
        ws.add_observation("x", actor="a", disposition="CERTAIN")


def test_observation_persists_and_report_includes_it(home: Path, evidence_file: Path):
    ws = _declare(home)
    res = ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation(
        "DB audit logs show SELECT on customer table",
        actor="a",
        evidence_refs=[res["sha256"][:16]],
    )

    reloaded = IncidentWorkspace.load(home, ws.incident_id)
    assert reloaded.observation(obs.observation_id).text == obs.text
    md = reloaded.generate_report(actor="a")
    assert "## Observations" in md
    assert obs.observation_id in md
    assert "DB audit logs show SELECT" in md


def test_observation_correction_is_append_only_and_audited(home: Path, evidence_file: Path):
    ws = _declare(home)
    res = ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("DB access from 10.0.0.5", actor="a", evidence_refs=[res["sha256"]])

    correction = ws.correct_observation(
        obs.observation_id,
        "DB access was from 10.0.0.6",
        actor="reviewer@example.com",
        reason="Analyst typo",
    )

    assert ws.observation(obs.observation_id).text == "DB access from 10.0.0.5"
    assert correction.amendment_type == "CORRECTION"
    assert correction.observation_id == obs.observation_id
    assert ws.verify()["observations"] is True
    entry = ws.audit_entries()[-1]
    assert entry.action == "observation-corrected"
    assert entry.actor == "reviewer@example.com"
    assert entry.detail["amendment_id"] == correction.amendment_id
    assert entry.detail["text_hash"] == correction.text_hash()


def test_observation_retraction_is_append_only_and_blocks_later_correction(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")

    retraction = ws.retract_observation(obs.observation_id, "Source log was wrong", actor="a")

    assert retraction.amendment_type == "RETRACTION"
    assert ws.observation_is_retracted(obs.observation_id) is True
    assert ws.observation(obs.observation_id).text == "Initial observation"
    assert ws.verify()["observations"] is True
    with pytest.raises(WorkspaceError, match="retracted"):
        ws.correct_observation(obs.observation_id, "new text", actor="a")
    with pytest.raises(WorkspaceError, match="already retracted"):
        ws.retract_observation(obs.observation_id, "again", actor="a")


def test_observation_amendments_reject_bad_input_and_closed_incident(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("Initial observation", actor="a")

    with pytest.raises(WorkspaceError, match="correction text"):
        ws.correct_observation(obs.observation_id, "   ", actor="a")
    with pytest.raises(WorkspaceError, match="retraction reason"):
        ws.retract_observation(obs.observation_id, "   ", actor="a")
    with pytest.raises(WorkspaceError, match="observation not found"):
        ws.correct_observation("OBS-NOPE", "x", actor="a")

    ws.close_incident(actor="a")
    with pytest.raises(WorkspaceError, match="observations are locked"):
        ws.correct_observation(obs.observation_id, "x", actor="a")


def test_report_includes_observation_amendments(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("Initial observation", actor="a")
    correction = ws.correct_observation(obs.observation_id, "Corrected observation", actor="a")
    retraction = ws.retract_observation(obs.observation_id, "Retracted after review", actor="a")

    md = ws.generate_report(actor="a")

    assert "### Observation amendments" in md
    assert correction.amendment_id in md
    assert retraction.amendment_id in md
    assert "Corrected observation" in md
    assert "Retracted after review" in md


def test_verify_observations_detects_amendment_tampering(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    amendment = ws.correct_observation(obs.observation_id, "Corrected observation", actor="a")

    data = json.loads(ws._observations_path.read_text(encoding="utf-8"))
    data["amendments"][0]["text"] = "Tampered correction"
    ws._observations_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["observations"] is False
    assert any(amendment.amendment_id in err for err in v["observation_errors"])
    assert any("missing matching audit event" in err for err in v["observation_errors"])


def test_verify_observations_detects_duplicate_ids_and_tampering(home: Path, evidence_file: Path):
    ws = _declare(home)
    res = ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("Legitimate observation", actor="a", evidence_refs=[res["sha256"]])

    data = json.loads(ws._observations_path.read_text(encoding="utf-8"))
    duplicate = dict(data["observations"][0])
    duplicate["text"] = "Tampered duplicate"
    data["observations"].append(duplicate)
    ws._observations_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["observations"] is False
    assert any("duplicate observation id" in err for err in v["observation_errors"])
    assert any("missing matching audit event" in err for err in v["observation_errors"])
    assert obs.observation_id in v["observation_errors"][0] or v["observation_errors"]


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
    entry = [
        e for e in ws.audit_entries()
        if e.action == "lifecycle-transition" and e.detail["to"] == "RESOLVED"
    ][-1]
    assert entry.detail["from"] == "INVESTIGATING"


def test_lifecycle_transition_advances_and_audits(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")

    ws.transition("CONTAINED", actor="a", note="Blocked egress")
    assert ws.state["status"] == "CONTAINED"
    entry = ws.audit_entries()[-1]
    assert entry.action == "lifecycle-transition"
    assert entry.detail == {
        "from": "INVESTIGATING",
        "to": "CONTAINED",
        "note": "Blocked egress",
    }


def test_lifecycle_supports_response_stages(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")

    ws.transition("CONTAINED", actor="a")
    ws.transition("ERADICATING", actor="a")
    ws.transition("RECOVERING", actor="a")

    assert ws.state["status"] == "RECOVERING"
    assert [e.detail["to"] for e in ws.audit_entries()
            if e.action == "lifecycle-transition"] == [
                "CONTAINED",
                "ERADICATING",
                "RECOVERING",
            ]


def test_lifecycle_transition_rejects_regression_and_closed(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    ws.transition("CONTAINED", actor="a")
    with pytest.raises(WorkspaceError, match="cannot move lifecycle"):
        ws.transition("INVESTIGATING", actor="a")

    ws.close_incident(actor="a")
    with pytest.raises(WorkspaceError, match="lifecycle is locked"):
        ws.transition("RESOLVED", actor="a")


def test_resolve_requires_green_preclosure_gates(home: Path, evidence_file: Path):
    ws = _declare(home)
    with pytest.raises(WorkspaceError, match="cannot resolve incident"):
        ws.transition("RESOLVED", actor="a")

    ws.add_evidence(str(evidence_file), note="n", actor="a")
    ws.transition("RESOLVED", actor="a", note="Customer impact ended")
    assert ws.state["status"] == "RESOLVED"
    assert ws.audit_entries()[-1].detail["to"] == "RESOLVED"


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
    assert ws.state["status"] == "OPEN"


def test_close_refuses_unmet_preclosure_gates(home: Path):
    ws = _declare(home)
    with pytest.raises(WorkspaceError, match="unmet pre-closure gates"):
        ws.close_incident(actor="a")
    assert ws.state["status"] == "OPEN"
    assert ws.is_closed is False


def test_forced_close_requires_reason_and_audits_override(home: Path):
    ws = _declare(home)
    with pytest.raises(WorkspaceError, match="forced closure requires a reason"):
        ws.close_incident(actor="a", force=True)

    md = ws.close_incident(actor="a", force=True, reason="False positive; no artifact available")
    assert "UNMET gates" in md
    assert ws.state["status"] == "CLOSED"
    assert ws.state["closure_forced"] is True
    assert ws.state["closure_reason"] == "False positive; no artifact available"
    actions = [e.action for e in ws.audit_entries()]
    assert "closure-override" in actions
    assert actions[-1] == "incident-closed"


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


def test_resolved_incident_locks_evidence_intake(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    ws.transition("RESOLVED", actor="a")

    late = evidence_file.parent / "late.log"
    late.write_text("late evidence\n", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="evidence intake is locked"):
        ws.add_evidence(str(late), note="late", actor="a")


def test_seal_requires_closed_incident_and_locks_final_state(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")

    with pytest.raises(WorkspaceError, match="must be closed"):
        ws.seal_incident(actor="a")

    ws.close_incident(actor="a")
    ws.seal_incident(actor="a")

    assert ws.state["status"] == "SEALED"
    assert ws.is_closed is True
    assert ws.is_sealed is True
    assert ws.audit_entries()[-1].action == "incident-sealed"
    with pytest.raises(WorkspaceError, match="sealed"):
        ws.close_incident(actor="a")


def test_list_incidents(home: Path):
    a = _declare(home)
    b = IncidentWorkspace.declare(home, title="second", severity="SEV3", actor="a")
    ids = IncidentWorkspace.list_incidents(home)
    assert a.incident_id in ids and b.incident_id in ids
    # most recent declare is the active one
    assert IncidentWorkspace.current_id(home) == b.incident_id
