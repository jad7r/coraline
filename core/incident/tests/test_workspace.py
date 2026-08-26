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
