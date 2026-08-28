"""Tests for the incident workspace domain layer (wired to the real core)."""
from __future__ import annotations

import json
import multiprocessing
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


def _add_observation_process(home: str, incident_id: str, text: str, queue) -> None:
    try:
        ws = IncidentWorkspace.load(Path(home), incident_id)
        obs = ws.add_observation(text, actor="worker")
        queue.put(("ok", obs.observation_id))
    except Exception as exc:  # pragma: no cover - surfaced through parent process
        queue.put(("err", repr(exc)))


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
    assert entry.detail["record_hash"] == correction.record_hash()
    assert entry.detail["text_hash"] == correction.text_hash()

    effective = ws.effective_observation(obs.observation_id)
    assert effective.current_status == "OBSERVED"
    assert effective.current_text == "DB access was from 10.0.0.6"
    assert effective.latest_correction == correction


def test_observation_retraction_is_append_only_and_blocks_later_correction(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")

    retraction = ws.retract_observation(obs.observation_id, "Source log was wrong", actor="a")

    assert retraction.amendment_type == "RETRACTION"
    assert ws.observation_is_retracted(obs.observation_id) is True
    assert ws.observation(obs.observation_id).text == "Initial observation"
    assert ws.verify()["observations"] is True
    effective = ws.effective_observation(obs.observation_id)
    assert effective.current_status == "RETRACTED"
    assert effective.current_text == "Source log was wrong"
    assert effective.retraction == retraction
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
    assert "RETRACTED" in md
    assert "Current text" in md
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


def test_verify_observations_detects_observation_metadata_tampering(home: Path):
    ws = _declare(home)
    obs = ws.add_observation(
        "Initial observation",
        actor="alice@example.com",
        disposition="SUSPECTED",
        subject="prod-db",
    )

    data = json.loads(ws._observations_path.read_text(encoding="utf-8"))
    data["observations"][0]["creator"] = "mallory@example.com"
    data["observations"][0]["disposition"] = "OBSERVED"
    data["observations"][0]["subject"] = "different-host"
    ws._observations_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["observations"] is False
    assert any(obs.observation_id in err for err in v["observation_errors"])


def test_verify_observations_detects_deleted_observation_record(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Observation to delete", actor="a")

    data = json.loads(ws._observations_path.read_text(encoding="utf-8"))
    data["observations"] = []
    ws._observations_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["observations"] is False
    assert any(f"{obs.observation_id}: audit event has no observation record" in err
               for err in v["observation_errors"])


def test_verify_observations_detects_deleted_amendment_record(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    amendment = ws.correct_observation(obs.observation_id, "Corrected observation", actor="a")

    data = json.loads(ws._observations_path.read_text(encoding="utf-8"))
    data["amendments"] = []
    ws._observations_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["observations"] is False
    assert any(f"{amendment.amendment_id}: audit event has no amendment record" in err
               for err in v["observation_errors"])


def test_verify_observations_detects_removed_observation_audit_event(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")

    lines = ws._audit_path.read_text(encoding="utf-8").splitlines()
    ws._audit_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    v = ws.verify()
    assert v["observations"] is False
    assert any(f"{obs.observation_id}: missing matching audit event" in err
               for err in v["observation_errors"])


def test_verify_observations_detects_correction_after_retraction_in_store(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    ws.retract_observation(obs.observation_id, "Retracted", actor="a")

    data = json.loads(ws._observations_path.read_text(encoding="utf-8"))
    correction = dict(data["amendments"][0])
    correction["amendment_id"] = "OAM-MANUALCORR1"
    correction["amendment_type"] = "CORRECTION"
    correction["created_at"] = "9999-01-01T00:00:00Z"
    correction["text"] = "Manual correction after retraction"
    correction["reason"] = "Bad persisted order"
    data["amendments"].append(correction)
    ws._observations_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["observations"] is False
    assert any("correction after retraction" in err for err in v["observation_errors"])


def test_effective_observation_uses_latest_correction_before_retraction(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Original", actor="a")
    first = ws.correct_observation(obs.observation_id, "First correction", actor="a")
    second = ws.correct_observation(obs.observation_id, "Second correction", actor="a")

    effective = ws.effective_observation(obs.observation_id)

    assert effective.current_text == "Second correction"
    assert effective.current_status == "OBSERVED"
    assert effective.latest_correction == second
    assert first in effective.amendments


def test_concurrent_observation_writes_are_serialized(home: Path):
    ws = _declare(home)
    ctx = multiprocessing.get_context("fork")
    queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=_add_observation_process,
            args=(str(home), ws.incident_id, f"Concurrent observation {idx}", queue),
        )
        for idx in range(6)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)

    results = [queue.get(timeout=2) for _ in processes]
    assert all(kind == "ok" for kind, _ in results), results
    assert all(process.exitcode == 0 for process in processes)

    reloaded = IncidentWorkspace.load(home, ws.incident_id)
    entries = reloaded.audit_entries()
    assert verify_audit(entries) == (True, None)
    observation_events = [e for e in entries if e.action == "observation-created"]
    assert len(observation_events) == 6
    assert [e.seq for e in entries] == list(range(1, len(entries) + 1))
    assert len(reloaded.observations()) == 6
    assert reloaded.verify()["observations"] is True


def test_partial_observation_write_without_audit_is_detected(home: Path, monkeypatch):
    ws = _declare(home)

    def fail_audit(*args, **kwargs):
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(ws, "_append_audit", fail_audit)
    with pytest.raises(RuntimeError, match="audit write failed"):
        ws.add_observation("Observation without audit", actor="a")

    reloaded = IncidentWorkspace.load(home, ws.incident_id)
    v = reloaded.verify()
    assert v["observations"] is False
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


# ---- subjects --------------------------------------------------------------- #

def test_create_subject_is_immutable_audited_and_verifiable(home: Path):
    ws = _declare(home)

    subject = ws.create_subject(
        subject_type="host",
        value="host-01",
        display_name="Compromised workstation",
        description="Initial infected endpoint",
        actor="analyst@example.com",
        metadata={"source": "edr", "critical": True},
    )

    assert subject.subject_id.startswith("SUB-")
    assert subject.incident_id == ws.incident_id
    assert subject.subject_type == "HOST"
    assert subject.value == "host-01"
    assert ws.subject(subject.subject_id) == subject
    assert ws.list_subjects() == [subject]
    assert ws.verify()["subjects"] is True
    entry = ws.audit_entries()[-1]
    assert entry.action == "subject-created"
    assert entry.actor == "analyst@example.com"
    assert entry.detail["subject_id"] == subject.subject_id
    assert entry.detail["record_hash"] == subject.record_hash()
    assert entry.detail["value_hash"] == subject.value_hash()


def test_subject_rejects_invalid_duplicate_and_closed_incident(home: Path):
    ws = _declare(home)

    with pytest.raises(WorkspaceError, match="invalid subject type"):
        ws.create_subject("ASSET", "host-01", actor="a")
    with pytest.raises(WorkspaceError, match="subject value must not be empty"):
        ws.create_subject("HOST", "   ", actor="a")
    with pytest.raises(WorkspaceError, match="metadata value"):
        ws.create_subject("HOST", "host-01", actor="a", metadata={"nested": {"x": "y"}})

    ws.create_subject("HOST", "host-01", actor="a")
    with pytest.raises(WorkspaceError, match="subject already exists"):
        ws.create_subject("HOST", "host-01", actor="a")

    ws.close_incident(actor="a", force=True, reason="subject lock test")
    with pytest.raises(WorkspaceError, match="subjects are locked"):
        ws.create_subject("HOST", "host-02", actor="a")


def test_subject_refs_on_observation_claim_and_action_are_verified(home: Path):
    ws = _declare(home)
    subject = ws.create_subject("HOST", "host-01", actor="a")
    obs = ws.add_observation("EDR shows unusual process", actor="a",
                             subject_refs=[subject.subject_id])
    claim = ws.add_claim("Host executed unusual process", actor="a",
                         observation_refs=[obs.observation_id],
                         subject_refs=[subject.subject_id])
    action = ws.create_action(
        "host-isolation",
        "Isolated host-01",
        actor="a",
        observation_refs=[obs.observation_id],
        claim_refs=[claim.claim_id],
        subject_refs=[subject.subject_id],
    )

    assert obs.subjects == (subject.subject_id,)
    assert claim.subjects == (subject.subject_id,)
    assert action.subjects == (subject.subject_id,)
    v = ws.verify()
    assert v["subjects"] is True
    assert v["observations"] is True
    assert v["claims"] is True
    assert v["actions"] is True


def test_subject_ref_rejects_nonexistent_path_and_foreign_incident(home: Path):
    ws = _declare(home)
    foreign = IncidentWorkspace.declare(home, title="foreign", severity="SEV3", actor="a")
    foreign_subject = foreign.create_subject("HOST", "foreign-host", actor="a")

    with pytest.raises(WorkspaceError, match="subject not found"):
        ws.add_observation("x", actor="a", subject_refs=[foreign_subject.subject_id])
    with pytest.raises(WorkspaceError, match="invalid subject reference"):
        ws.add_observation("x", actor="a", subject_refs=["../SUB-BAD"])


def test_verify_subjects_detects_tampering_and_deleted_subject(home: Path):
    ws = _declare(home)
    subject = ws.create_subject("EMAIL", "user@example.com", actor="a")

    data = json.loads(ws._subjects_path.read_text(encoding="utf-8"))
    data["subjects"][0]["value"] = "attacker@example.com"
    ws._subjects_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["subjects"] is False
    assert any(subject.subject_id in err for err in v["subject_errors"])

    data["subjects"] = []
    ws._subjects_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    v = ws.verify()
    assert v["subjects"] is False
    assert any("audit event has no subject record" in err for err in v["subject_errors"])


def test_verify_detects_deleted_subject_referenced_by_records(home: Path):
    ws = _declare(home)
    subject = ws.create_subject("HOST", "host-01", actor="a")
    obs = ws.add_observation("Observation with subject", actor="a",
                             subject_refs=[subject.subject_id])

    data = json.loads(ws._subjects_path.read_text(encoding="utf-8"))
    data["subjects"] = []
    ws._subjects_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["observations"] is False
    assert any(f"{obs.observation_id}: missing subject {subject.subject_id}" in err
               for err in v["observation_errors"])


# ---- claims ----------------------------------------------------------------- #

def test_add_claim_references_observations_and_audits(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("CloudTrail shows unusual database access", actor="analyst")

    claim = ws.add_claim(
        "Production database was accessed from an unusual source",
        actor="lead@example.com",
        observation_refs=[obs.observation_id],
        status="SUPPORTED",
        subject="prod-db",
    )

    assert claim.claim_id.startswith("CLM-")
    assert claim.incident_id == ws.incident_id
    assert claim.observations == (obs.observation_id,)
    assert claim.subject == "prod-db"
    assert ws.state["claim_count"] == 1
    v = ws.verify()
    assert v["claims"] is True
    entry = ws.audit_entries()[-1]
    assert entry.action == "claim-created"
    assert entry.actor == "lead@example.com"
    assert entry.detail["claim_id"] == claim.claim_id
    assert entry.detail["observations"] == [obs.observation_id]
    assert entry.detail["record_hash"] == claim.record_hash()
    assert entry.detail["text_hash"] == claim.text_hash()


def test_claim_rejects_missing_path_cross_incident_and_retracted_observations(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    other = IncidentWorkspace.declare(home, title="Other", severity="SEV3", actor="a")
    other_obs = other.add_observation("Other incident observation", actor="a")

    with pytest.raises(WorkspaceError, match="requires at least one observation"):
        ws.add_claim("Unsupported claim", actor="a", observation_refs=[])
    with pytest.raises(WorkspaceError, match="invalid observation reference"):
        ws.add_claim("Path bypass", actor="a", observation_refs=["/tmp/OBS-NOPE"])
    with pytest.raises(WorkspaceError, match="observation not found"):
        ws.add_claim("Missing observation", actor="a", observation_refs=["OBS-NOPE"])
    with pytest.raises(WorkspaceError, match="observation not found"):
        ws.add_claim("Cross incident", actor="a", observation_refs=[other_obs.observation_id])

    ws.retract_observation(obs.observation_id, "Invalid source", actor="a")
    with pytest.raises(WorkspaceError, match="retracted observation"):
        ws.add_claim("Claim after retraction", actor="a", observation_refs=[obs.observation_id])


def test_claim_rejects_malformed_input_and_closed_incident(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("Initial observation", actor="a")

    with pytest.raises(WorkspaceError, match="claim text must not be empty"):
        ws.add_claim("   ", actor="a", observation_refs=[obs.observation_id])
    with pytest.raises(WorkspaceError, match="invalid claim status"):
        ws.add_claim("x", actor="a", observation_refs=[obs.observation_id], status="CERTAIN")

    ws.close_incident(actor="a")
    with pytest.raises(WorkspaceError, match="claims are locked"):
        ws.add_claim("Too late", actor="a", observation_refs=[obs.observation_id])


def test_claim_persists_and_report_includes_it(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("DB audit logs show SELECT on customer table", actor="a")
    claim = ws.add_claim("Customer table was queried", actor="a", observation_refs=[obs.observation_id])

    reloaded = IncidentWorkspace.load(home, ws.incident_id)

    assert reloaded.claim(claim.claim_id).text == claim.text
    md = reloaded.generate_report(actor="a")
    assert "## Claims" in md
    assert claim.claim_id in md
    assert obs.observation_id in md
    assert "Customer table was queried" in md


def test_verify_claims_detects_deleted_claim_record(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Derived claim", actor="a", observation_refs=[obs.observation_id])

    data = json.loads(ws._claims_path.read_text(encoding="utf-8"))
    data["claims"] = []
    ws._claims_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["claims"] is False
    assert any(f"{claim.claim_id}: audit event has no claim record" in err
               for err in v["claim_errors"])


def test_verify_claims_detects_claim_metadata_tampering(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Derived claim", actor="a", observation_refs=[obs.observation_id])

    data = json.loads(ws._claims_path.read_text(encoding="utf-8"))
    data["claims"][0]["creator"] = "mallory@example.com"
    data["claims"][0]["status"] = "SUPPORTED"
    ws._claims_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["claims"] is False
    assert any(claim.claim_id in err for err in v["claim_errors"])


def test_verify_claims_detects_removed_claim_audit_event(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Derived claim", actor="a", observation_refs=[obs.observation_id])

    lines = ws._audit_path.read_text(encoding="utf-8").splitlines()
    ws._audit_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    v = ws.verify()
    assert v["claims"] is False
    assert any(f"{claim.claim_id}: missing matching audit event" in err
               for err in v["claim_errors"])


def test_verify_claims_detects_duplicate_ids_and_tampering(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Derived claim", actor="a", observation_refs=[obs.observation_id])

    data = json.loads(ws._claims_path.read_text(encoding="utf-8"))
    duplicate = dict(data["claims"][0])
    duplicate["text"] = "Tampered duplicate claim"
    data["claims"].append(duplicate)
    ws._claims_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["claims"] is False
    assert any("duplicate claim id" in err for err in v["claim_errors"])
    assert any("missing matching audit event" in err for err in v["claim_errors"])
    assert claim.claim_id in v["claim_errors"][0] or v["claim_errors"]


def test_claim_remains_verifiable_when_supporting_observation_is_later_retracted(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Derived claim", actor="a", observation_refs=[obs.observation_id])

    ws.retract_observation(obs.observation_id, "Invalid source", actor="a")

    v = ws.verify()
    assert v["claims"] is True
    assert ws.claim(claim.claim_id).observations == (obs.observation_id,)


def test_claim_correction_status_and_withdrawal_are_append_only_and_audited(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Original claim", actor="a", observation_refs=[obs.observation_id])

    correction = ws.correct_claim(
        claim.claim_id,
        "Corrected claim",
        actor="reviewer@example.com",
        reason="Use precise wording",
    )
    status = ws.update_claim_status(
        claim.claim_id,
        "SUPPORTED",
        actor="lead@example.com",
        reason="Second analyst review completed",
    )
    withdrawal = ws.withdraw_claim(
        claim.claim_id,
        "Claim superseded by later analysis",
        actor="lead@example.com",
    )

    assert ws.claim(claim.claim_id).text == "Original claim"
    effective = ws.effective_claim(claim.claim_id)
    assert effective.current_status == "WITHDRAWN"
    assert effective.current_text == "Claim superseded by later analysis"
    assert effective.latest_correction == correction
    assert effective.latest_status == status
    assert effective.withdrawal == withdrawal
    assert ws.verify()["claims"] is True
    actions = [e.action for e in ws.audit_entries()]
    assert "claim-corrected" in actions
    assert "claim-status-updated" in actions
    assert "claim-withdrawn" in actions

    with pytest.raises(WorkspaceError, match="withdrawn"):
        ws.correct_claim(claim.claim_id, "too late", actor="a")
    with pytest.raises(WorkspaceError, match="withdrawn"):
        ws.update_claim_status(claim.claim_id, "REFUTED", actor="a", reason="too late")
    with pytest.raises(WorkspaceError, match="already withdrawn"):
        ws.withdraw_claim(claim.claim_id, "again", actor="a")


def test_claim_amendments_reject_bad_input_and_closed_incident(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Initial claim", actor="a", observation_refs=[obs.observation_id])

    with pytest.raises(WorkspaceError, match="correction text"):
        ws.correct_claim(claim.claim_id, "   ", actor="a")
    with pytest.raises(WorkspaceError, match="claim status reason"):
        ws.update_claim_status(claim.claim_id, "SUPPORTED", actor="a", reason="   ")
    with pytest.raises(WorkspaceError, match="invalid claim status"):
        ws.update_claim_status(claim.claim_id, "CERTAIN", actor="a", reason="review")
    with pytest.raises(WorkspaceError, match="withdrawal reason"):
        ws.withdraw_claim(claim.claim_id, "   ", actor="a")
    with pytest.raises(WorkspaceError, match="claim not found"):
        ws.correct_claim("CLM-NOPE", "x", actor="a")

    ws.close_incident(actor="a")
    with pytest.raises(WorkspaceError, match="claims are locked"):
        ws.correct_claim(claim.claim_id, "x", actor="a")


def test_report_includes_claim_amendments(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Initial claim", actor="a", observation_refs=[obs.observation_id])
    correction = ws.correct_claim(claim.claim_id, "Corrected claim", actor="a")
    status = ws.update_claim_status(claim.claim_id, "SUPPORTED", actor="a", reason="Review complete")

    md = ws.generate_report(actor="a")

    assert "### Claim amendments" in md
    assert "Current claim" in md
    assert correction.amendment_id in md
    assert status.amendment_id in md
    assert "Corrected claim" in md
    assert "Review complete" in md


def test_verify_claims_detects_claim_amendment_tampering(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Initial claim", actor="a", observation_refs=[obs.observation_id])
    amendment = ws.correct_claim(claim.claim_id, "Corrected claim", actor="a")

    data = json.loads(ws._claims_path.read_text(encoding="utf-8"))
    data["amendments"][0]["text"] = "Tampered correction"
    ws._claims_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["claims"] is False
    assert any(amendment.amendment_id in err for err in v["claim_errors"])
    assert any("missing matching audit event" in err for err in v["claim_errors"])


def test_verify_claims_detects_deleted_claim_amendment_record(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Initial claim", actor="a", observation_refs=[obs.observation_id])
    amendment = ws.correct_claim(claim.claim_id, "Corrected claim", actor="a")

    data = json.loads(ws._claims_path.read_text(encoding="utf-8"))
    data["amendments"] = []
    ws._claims_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["claims"] is False
    assert any(f"{amendment.amendment_id}: audit event has no claim amendment record" in err
               for err in v["claim_errors"])


def test_verify_claims_detects_status_after_withdrawal_in_store(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Initial claim", actor="a", observation_refs=[obs.observation_id])
    ws.withdraw_claim(claim.claim_id, "Withdrawn", actor="a")

    data = json.loads(ws._claims_path.read_text(encoding="utf-8"))
    status = dict(data["amendments"][0])
    status["amendment_id"] = "CAM-MANUALSTAT1"
    status["amendment_type"] = "STATUS"
    status["created_at"] = "9999-01-01T00:00:00Z"
    status["status"] = "SUPPORTED"
    status["text"] = "Manual status after withdrawal"
    status["reason"] = "Bad persisted order"
    data["amendments"].append(status)
    ws._claims_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["claims"] is False
    assert any("status after withdrawal" in err for err in v["claim_errors"])


# ---- actions ---------------------------------------------------------------- #

def test_create_action_references_records_and_audits(home: Path, evidence_file: Path):
    ws = _declare(home)
    res = ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("Credential used from unusual IP", actor="a", evidence_refs=[res["sha256"]])
    claim = ws.add_claim("Credential was compromised", actor="a", observation_refs=[obs.observation_id])

    action = ws.create_action(
        action_type="credential-revocation",
        description="Revoked exposed deployment credential",
        actor="responder@example.com",
        status="COMPLETED",
        subject="deploy-key",
        observation_refs=[obs.observation_id],
        claim_refs=[claim.claim_id],
        evidence_refs=[res["sha256"][:16]],
        outcome="Credential revoked in IAM",
    )

    assert action.action_id.startswith("ACT-")
    assert action.incident_id == ws.incident_id
    assert action.observations == (obs.observation_id,)
    assert action.claims == (claim.claim_id,)
    assert action.evidence == (res["sha256"],)
    assert ws.state["action_count"] == 1
    v = ws.verify()
    assert v["actions"] is True
    entry = ws.audit_entries()[-1]
    assert entry.action == "action-created"
    assert entry.actor == "responder@example.com"
    assert entry.detail["action_id"] == action.action_id
    assert entry.detail["record_hash"] == action.record_hash()
    assert entry.detail["description_hash"] == action.description_hash()


def test_action_rejects_invalid_references_and_malformed_input(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")

    with pytest.raises(WorkspaceError, match="action type"):
        ws.create_action("   ", "Do thing", actor="a")
    with pytest.raises(WorkspaceError, match="action description"):
        ws.create_action("containment", "   ", actor="a")
    with pytest.raises(WorkspaceError, match="invalid action status"):
        ws.create_action("containment", "Do thing", actor="a", status="STARTED")
    with pytest.raises(WorkspaceError, match="observation not found"):
        ws.create_action("containment", "Do thing", actor="a", observation_refs=["OBS-NOPE"])
    with pytest.raises(WorkspaceError, match="claim not found"):
        ws.create_action("containment", "Do thing", actor="a", claim_refs=["CLM-NOPE"])
    with pytest.raises(WorkspaceError, match="invalid claim reference"):
        ws.create_action("containment", "Do thing", actor="a", claim_refs=["/tmp/CLM-NOPE"])
    with pytest.raises(WorkspaceError, match="evidence not found"):
        ws.create_action("containment", "Do thing", actor="a", evidence_refs=["0" * 64])


def test_action_amendments_are_append_only_and_audited(home: Path):
    ws = _declare(home)
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Initial claim", actor="a", observation_refs=[obs.observation_id])
    action = ws.create_action(
        "host-isolation",
        "Isolate host from network",
        actor="a",
        claim_refs=[claim.claim_id],
    )

    correction = ws.amend_action(action.action_id, "Isolate host-01 from network", actor="a",
                                 reason="Add hostname")
    status = ws.update_action_status(action.action_id, "INITIATED", actor="a",
                                     reason="EDR command sent")
    outcome = ws.update_action_outcome(action.action_id, "Host isolation confirmed", actor="a",
                                       reason="EDR state verified")
    cancellation = ws.cancel_action(action.action_id, "Action superseded", actor="a")

    assert ws.action(action.action_id).description == "Isolate host from network"
    effective = ws.effective_action(action.action_id)
    assert effective.current_status == "CANCELLED"
    assert effective.current_description == "Isolate host-01 from network"
    assert effective.current_outcome == "Host isolation confirmed"
    assert effective.latest_correction == correction
    assert effective.latest_status == status
    assert effective.latest_outcome == outcome
    assert effective.cancellation == cancellation
    assert ws.verify()["actions"] is True
    actions = [entry.action for entry in ws.audit_entries()]
    assert "action-corrected" in actions
    assert "action-status-updated" in actions
    assert "action-outcome-updated" in actions
    assert "action-cancelled" in actions

    with pytest.raises(WorkspaceError, match="cancelled"):
        ws.amend_action(action.action_id, "too late", actor="a")
    with pytest.raises(WorkspaceError, match="cancelled"):
        ws.update_action_status(action.action_id, "COMPLETED", actor="a", reason="too late")
    with pytest.raises(WorkspaceError, match="cancelled"):
        ws.update_action_outcome(action.action_id, "too late", actor="a")
    with pytest.raises(WorkspaceError, match="already cancelled"):
        ws.cancel_action(action.action_id, "again", actor="a")


def test_action_amendments_reject_bad_input_and_closed_incident(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    action = ws.create_action("containment", "Block source IP", actor="a")

    with pytest.raises(WorkspaceError, match="correction text"):
        ws.amend_action(action.action_id, "   ", actor="a")
    with pytest.raises(WorkspaceError, match="status reason"):
        ws.update_action_status(action.action_id, "INITIATED", actor="a", reason="   ")
    with pytest.raises(WorkspaceError, match="invalid action status"):
        ws.update_action_status(action.action_id, "STARTED", actor="a", reason="review")
    with pytest.raises(WorkspaceError, match="use cancel_action"):
        ws.update_action_status(action.action_id, "CANCELLED", actor="a", reason="review")
    with pytest.raises(WorkspaceError, match="outcome must not be empty"):
        ws.update_action_outcome(action.action_id, "   ", actor="a")
    with pytest.raises(WorkspaceError, match="cancellation reason"):
        ws.cancel_action(action.action_id, "   ", actor="a")
    with pytest.raises(WorkspaceError, match="action not found"):
        ws.amend_action("ACT-NOPE", "x", actor="a")

    ws.close_incident(actor="a")
    with pytest.raises(WorkspaceError, match="actions are locked"):
        ws.create_action("too-late", "Too late", actor="a")
    with pytest.raises(WorkspaceError, match="actions are locked"):
        ws.amend_action(action.action_id, "Too late", actor="a")


def test_report_includes_actions_and_action_amendments(home: Path, evidence_file: Path):
    ws = _declare(home)
    ws.add_evidence(str(evidence_file), note="n", actor="a")
    obs = ws.add_observation("Initial observation", actor="a")
    claim = ws.add_claim("Initial claim", actor="a", observation_refs=[obs.observation_id])
    action = ws.create_action("credential-revocation", "Revoke credential", actor="a",
                              claim_refs=[claim.claim_id], observation_refs=[obs.observation_id])
    amendment = ws.update_action_outcome(action.action_id, "Credential revoked", actor="a")

    md = ws.generate_report(actor="a")

    assert "## Actions" in md
    assert "### Action amendments" in md
    assert action.action_id in md
    assert amendment.amendment_id in md
    assert claim.claim_id in md
    assert obs.observation_id in md
    assert "Credential revoked" in md


def test_verify_actions_detects_deleted_action_record(home: Path):
    ws = _declare(home)
    action = ws.create_action("containment", "Block IP", actor="a")

    data = json.loads(ws._actions_path.read_text(encoding="utf-8"))
    data["actions"] = []
    ws._actions_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["actions"] is False
    assert any(f"{action.action_id}: audit event has no action record" in err
               for err in v["action_errors"])


def test_verify_actions_detects_action_metadata_tampering(home: Path):
    ws = _declare(home)
    action = ws.create_action("containment", "Block IP", actor="a")

    data = json.loads(ws._actions_path.read_text(encoding="utf-8"))
    data["actions"][0]["description"] = "Tampered action"
    ws._actions_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["actions"] is False
    assert any(action.action_id in err for err in v["action_errors"])


def test_verify_actions_detects_amendment_tampering_and_deletion(home: Path):
    ws = _declare(home)
    action = ws.create_action("containment", "Block IP", actor="a")
    amendment = ws.amend_action(action.action_id, "Block IP 203.0.113.10", actor="a")

    data = json.loads(ws._actions_path.read_text(encoding="utf-8"))
    data["amendments"][0]["text"] = "Tampered correction"
    ws._actions_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["actions"] is False
    assert any(amendment.amendment_id in err for err in v["action_errors"])

    reloaded = IncidentWorkspace.load(home, ws.incident_id)
    data = json.loads(reloaded._actions_path.read_text(encoding="utf-8"))
    data["amendments"] = []
    reloaded._actions_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = reloaded.verify()
    assert v["actions"] is False
    assert any(f"{amendment.amendment_id}: audit event has no action amendment record" in err
               for err in v["action_errors"])


def test_verify_actions_detects_status_after_cancellation_in_store(home: Path):
    ws = _declare(home)
    action = ws.create_action("containment", "Block IP", actor="a")
    ws.cancel_action(action.action_id, "No longer needed", actor="a")

    data = json.loads(ws._actions_path.read_text(encoding="utf-8"))
    status = dict(data["amendments"][0])
    status["amendment_id"] = "AAM-MANUALSTAT1"
    status["amendment_type"] = "STATUS"
    status["created_at"] = "9999-01-01T00:00:00Z"
    status["status"] = "COMPLETED"
    status["text"] = "Manual status after cancellation"
    status["reason"] = "Bad persisted order"
    data["amendments"].append(status)
    ws._actions_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    v = ws.verify()
    assert v["actions"] is False
    assert any("status after cancellation" in err for err in v["action_errors"])


# ---- decisions -------------------------------------------------------------- #

def _seed_decision_refs(ws: IncidentWorkspace, evidence_file: Path):
    evidence = ws.add_evidence(str(evidence_file), note="n", actor="a")
    subject = ws.create_subject("HOST", "host-01", actor="a")
    obs = ws.add_observation("EDR shows malware execution", actor="a",
                             evidence_refs=[evidence["sha256"]],
                             subject_refs=[subject.subject_id])
    claim = ws.add_claim("Host was compromised", actor="a",
                         observation_refs=[obs.observation_id],
                         subject_refs=[subject.subject_id])
    action = ws.create_action("host-isolation", "Isolated host-01", actor="a",
                              claim_refs=[claim.claim_id],
                              observation_refs=[obs.observation_id],
                              evidence_refs=[evidence["sha256"]],
                              subject_refs=[subject.subject_id])
    return evidence, subject, obs, claim, action


def test_create_decision_references_records_and_audits(home: Path, evidence_file: Path):
    ws = _declare(home)
    evidence, subject, obs, claim, action = _seed_decision_refs(ws, evidence_file)

    decision = ws.create_decision(
        "authorize-recovery",
        "Authorize recovery of host-01",
        "Containment action completed and supporting evidence reviewed",
        decided_by="lead@example.com",
        actor="lead@example.com",
        subject_refs=[subject.subject_id],
        evidence_refs=[evidence["sha256"][:16]],
        observation_refs=[obs.observation_id],
        claim_refs=[claim.claim_id],
        action_refs=[action.action_id],
        alternatives_considered=["Keep host isolated for more analysis"],
    )

    assert decision.decision_id.startswith("DEC-")
    assert decision.subjects == (subject.subject_id,)
    assert decision.evidence == (evidence["sha256"],)
    assert decision.observations == (obs.observation_id,)
    assert decision.claims == (claim.claim_id,)
    assert decision.actions == (action.action_id,)
    assert ws.verify()["decisions"] is True
    entry = ws.audit_entries()[-1]
    assert entry.action == "decision-created"
    assert entry.detail["decision_id"] == decision.decision_id
    assert entry.detail["record_hash"] == decision.record_hash()


def test_decision_rejects_invalid_references_and_ai_authority(home: Path):
    ws = _declare(home)

    with pytest.raises(WorkspaceError, match="observation not found"):
        ws.create_decision("notify", "Notify customer", "Impact confirmed",
                           decided_by="lead", actor="lead",
                           observation_refs=["OBS-NOPE"])
    with pytest.raises(WorkspaceError, match="subject not found"):
        ws.create_decision("notify", "Notify customer", "Impact confirmed",
                           decided_by="lead", actor="lead",
                           subject_refs=["SUB-NOPE"])
    with pytest.raises(WorkspaceError, match="human authority"):
        ws.create_decision("notify", "Notify customer", "Impact confirmed",
                           decided_by="ai:assistant", actor="lead")
    with pytest.raises(WorkspaceError, match="APPROVED decisions require"):
        ws.create_decision("notify", "Notify customer", "Impact confirmed",
                           decided_by="lead", actor="lead", status="APPROVED")
    with pytest.raises(WorkspaceError, match="human authority"):
        ws.create_decision("notify", "Notify customer", "Impact confirmed",
                           decided_by="lead", actor="lead", status="APPROVED",
                           approved_by="llm:agent")


def test_decision_amendments_are_append_only_and_effective_state_is_deterministic(home: Path):
    ws = _declare(home)
    decision = ws.create_decision(
        "containment",
        "Delay host isolation",
        "Need volatile memory capture",
        decided_by="lead",
        actor="lead",
    )

    correction = ws.amend_decision(
        decision.decision_id,
        "Delay host isolation until memory capture completes",
        actor="lead",
        reason="Clarify condition",
    )
    rationale = ws.update_decision_rationale(
        decision.decision_id,
        "Forensic memory image is needed before network isolation",
        actor="lead",
        reason="Add forensic rationale",
    )
    approval = ws.approve_decision(
        decision.decision_id,
        approved_by="director@example.com",
        actor="lead",
        reason="Director approved containment delay",
    )

    assert ws.decision(decision.decision_id).statement == "Delay host isolation"
    effective = ws.effective_decision(decision.decision_id)
    assert effective.current_statement == correction.text
    assert effective.current_rationale == rationale.rationale
    assert effective.current_status == "APPROVED"
    assert effective.current_approved_by == "director@example.com"
    assert effective.approval == approval
    assert ws.verify()["decisions"] is True


def test_decision_terminal_status_blocks_later_amendment(home: Path):
    ws = _declare(home)
    decision = ws.create_decision("notify", "Notify customer", "Impact confirmed",
                                  decided_by="lead", actor="lead")
    ws.reject_decision(decision.decision_id, actor="lead", reason="Legal requested delay")

    with pytest.raises(WorkspaceError, match="terminal"):
        ws.amend_decision(decision.decision_id, "Notify later", actor="lead")
    with pytest.raises(WorkspaceError, match="cannot move decision"):
        ws.approve_decision(decision.decision_id, "director", actor="lead", reason="late")


def test_decision_supersession_rejects_self_and_foreign(home: Path):
    ws = _declare(home)
    first = ws.create_decision("notify", "Notify customer", "Impact confirmed",
                               decided_by="lead", actor="lead")
    second = ws.create_decision("notify", "Delay notification", "Legal review pending",
                                decided_by="lead", actor="lead")
    foreign = IncidentWorkspace.declare(home, title="foreign", severity="SEV3", actor="a")
    foreign_decision = foreign.create_decision("notify", "Foreign", "Different case",
                                               decided_by="lead", actor="lead")

    with pytest.raises(WorkspaceError, match="cannot supersede itself"):
        ws.supersede_decision(first.decision_id, first.decision_id, actor="lead", reason="bad")
    with pytest.raises(WorkspaceError, match="decision not found"):
        ws.supersede_decision(first.decision_id, foreign_decision.decision_id,
                              actor="lead", reason="foreign")

    amendment = ws.supersede_decision(first.decision_id, second.decision_id,
                                      actor="lead", reason="Better decision")
    assert amendment.amendment_type == "SUPERSEDE"
    assert ws.effective_decision(first.decision_id).current_status == "SUPERSEDED"
    assert ws.verify()["decisions"] is True


def test_decision_tampering_and_deleted_amendment_are_detected(home: Path):
    ws = _declare(home)
    decision = ws.create_decision("notify", "Notify customer", "Impact confirmed",
                                  decided_by="lead", actor="lead")
    amendment = ws.amend_decision(decision.decision_id, "Notify affected customer", actor="lead")

    data = json.loads(ws._decisions_path.read_text(encoding="utf-8"))
    data["decisions"][0]["rationale"] = "Tampered rationale"
    ws._decisions_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    v = ws.verify()
    assert v["decisions"] is False
    assert any(decision.decision_id in err for err in v["decision_errors"])

    data["decisions"][0]["rationale"] = "Impact confirmed"
    data["amendments"] = []
    ws._decisions_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    v = ws.verify()
    assert v["decisions"] is False
    assert any(f"{amendment.amendment_id}: audit event has no decision amendment record" in err
               for err in v["decision_errors"])


def test_decision_report_and_closed_incident_lock(home: Path, evidence_file: Path):
    ws = _declare(home)
    _, subject, obs, claim, action = _seed_decision_refs(ws, evidence_file)
    decision = ws.create_decision(
        "authorize-recovery",
        "Authorize recovery",
        "Containment complete",
        decided_by="lead",
        actor="lead",
        subject_refs=[subject.subject_id],
        observation_refs=[obs.observation_id],
        claim_refs=[claim.claim_id],
        action_refs=[action.action_id],
    )

    md = ws.generate_report(actor="lead")
    assert "## Decisions" in md
    assert decision.decision_id in md
    assert "Authorize recovery" in md

    ws.close_incident(actor="lead")
    with pytest.raises(WorkspaceError, match="decisions are locked"):
        ws.create_decision("late", "Late decision", "Too late", decided_by="lead", actor="lead")


# ---- case graph ------------------------------------------------------------- #

def test_case_graph_rebuild_is_deterministic_and_uses_explicit_edges(home: Path, evidence_file: Path):
    ws = _declare(home)
    evidence, subject, obs, claim, action = _seed_decision_refs(ws, evidence_file)
    decision = ws.create_decision(
        "authorize-recovery",
        "Authorize recovery",
        "Containment complete",
        decided_by="lead",
        actor="lead",
        subject_refs=[subject.subject_id],
        evidence_refs=[evidence["sha256"]],
        observation_refs=[obs.observation_id],
        claim_refs=[claim.claim_id],
        action_refs=[action.action_id],
    )

    first = ws.case_graph().to_dict()
    second = IncidentWorkspace.load(home, ws.incident_id).case_graph().to_dict()

    assert first == second
    graph = ws.case_graph()
    assert graph.verify() == (True, [])
    summary = graph.summary()
    assert summary["evidence"] == 1
    assert summary["subject"] == 1
    assert summary["observation"] == 1
    assert summary["claim"] == 1
    assert summary["action"] == 1
    assert summary["decision"] == 1
    edge_ids = {edge.edge_id for edge in graph.edges}
    assert f"EVIDENCE:{evidence['sha256']}--SUPPORTS-->OBSERVATION:{obs.observation_id}" in edge_ids
    assert f"OBSERVATION:{obs.observation_id}--SUPPORTS-->CLAIM:{claim.claim_id}" in edge_ids
    assert f"CLAIM:{claim.claim_id}--JUSTIFIES-->ACTION:{action.action_id}" in edge_ids
    assert f"ACTION:{action.action_id}--INFORMS-->DECISION:{decision.decision_id}" in edge_ids
    assert f"SUBJECT:{subject.subject_id}--CONSIDERED_IN-->DECISION:{decision.decision_id}" in edge_ids


def test_case_graph_decision_supersession_edge(home: Path):
    ws = _declare(home)
    old = ws.create_decision("notify", "Notify now", "Impact likely",
                             decided_by="lead", actor="lead")
    new = ws.create_decision("notify", "Delay notification", "Legal review",
                             decided_by="lead", actor="lead")
    ws.supersede_decision(old.decision_id, new.decision_id, actor="lead", reason="Legal")

    edge_ids = {edge.edge_id for edge in ws.case_graph().edges}
    assert f"DECISION:{new.decision_id}--SUPERSEDES-->DECISION:{old.decision_id}" in edge_ids


def test_case_graph_validation_detects_invalid_edges():
    from core.incident.case_graph import CaseGraph, CaseGraphEdge, CaseGraphNode

    graph = CaseGraph(
        incident_id="INC-X",
        nodes=(
            CaseGraphNode("CLAIM:CLM-1", "CLAIM", "CLM-1", "claim"),
            CaseGraphNode("EVIDENCE:abc", "EVIDENCE", "abc", "evidence"),
        ),
        edges=(
            CaseGraphEdge("bad", "CLAIM:CLM-1", "EVIDENCE:abc", "SUPPORTS"),
            CaseGraphEdge("dangling", "MISSING:1", "EVIDENCE:abc", "SUPPORTS"),
        ),
    )

    ok, errors = graph.verify()
    assert ok is False
    assert any("invalid edge" in err for err in errors)
    assert any("dangling source" in err for err in errors)


def test_report_includes_case_relationships(home: Path, evidence_file: Path):
    ws = _declare(home)
    _, subject, obs, claim, action = _seed_decision_refs(ws, evidence_file)
    decision = ws.create_decision(
        "authorize-recovery",
        "Authorize recovery",
        "Containment complete",
        decided_by="lead",
        actor="lead",
        subject_refs=[subject.subject_id],
        observation_refs=[obs.observation_id],
        claim_refs=[claim.claim_id],
        action_refs=[action.action_id],
    )

    md = ws.generate_report(actor="lead")

    assert "## Case relationships" in md
    assert f"CLAIM:{claim.claim_id}` --JUSTIFIES--> `ACTION:{action.action_id}" in md
    assert f"ACTION:{action.action_id}` --INFORMS--> `DECISION:{decision.decision_id}" in md


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
