"""Adversarial checkpoint tests using real core records and ephemeral keys."""
import base64
import json
import random
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.incident import IncidentWorkspace, WorkspaceError
from core.evidence.integrity import signing
from core.incident import snapshots as s

WHEN = datetime(2026, 9, 20, 12, 30, tzinfo=timezone.utc)


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.delenv("CORELINE_SNAPSHOT_VERIFY_KEY", raising=False)
    ws = IncidentWorkspace.declare(tmp_path / "incidents", title="Snapshot test", severity="SEV2", actor="analyst")
    private = tmp_path / "external" / "snapshot.key"
    public = ws.home / "trust" / "snapshot.verify.json"
    s.generate_key_files(ws.home, private, public)
    key = s.load_private_key(private, ws.home)
    return ws, key, s.SnapshotStore(ws)


def capture(case):
    ws, key, store = case
    return store.create(key, "analyst", WHEN)


def sid(document):
    return document["payload"]["snapshot_id"]


def files(root):
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in root.rglob("*") if p.is_file()}


def populate(ws, tmp_path):
    evidence = tmp_path / "alert.log"
    evidence.write_text("preserved evidence")
    ws.add_evidence(str(evidence), "event", "analyst")
    subject = ws.create_subject("HOST", "original", "analyst")
    obs = ws.add_observation("original", "analyst", subject_refs=[subject.subject_id])
    claim = ws.add_claim("original", "analyst", [obs.observation_id])
    action = ws.create_action("contain", "original", "analyst", claim_refs=[claim.claim_id])
    ws.create_decision("review", "original", "reason", "human", "analyst", action_refs=[action.action_id])
    return obs, claim, action


def test_checkpoint_is_read_only_for_authoritative_state_and_verification(case):
    ws, key, store = case
    original = files(ws.dir)
    document = capture(case)
    for path, values in original.items():
        assert files(ws.dir)[path] == values
    ws._key_path.unlink()  # Snapshot verification needs no private signing key.
    before = files(ws.home)
    assert store.verify_snapshot(sid(document))["valid"]
    assert store.verify_chain()["valid"]
    assert store.compare_current(sid(document))["current_state_matches"]
    assert ws.verify()["ok"]
    assert files(ws.home) == before
    assert ws.snapshot_report().find(sid(document)) >= 0


def test_determinism_reload_key_order_record_order_and_ignored_files(case):
    ws, _, store = case
    ws.add_observation("first", "analyst")
    ws.add_observation("second", "analyst")
    initial = s.inventory(ws)
    reloaded = IncidentWorkspace.load(ws.home, ws.incident_id)
    assert s.inventory(reloaded) == initial
    p = ws.dir / "observations.json"
    data = json.loads(p.read_text())
    data["observations"].reverse()
    p.write_text(json.dumps(dict(reversed(list(data.items()))), indent=4))
    (ws.dir / "report.md").write_text("derived")
    (ws.dir / "graph-cache.json").write_text("derived")
    assert s.inventory(ws) == initial
    document = capture(case)
    second = capture(case)
    assert document["payload"]["incident_state_digest"] == second["payload"]["incident_state_digest"]
    assert sid(document) != sid(second)
    assert s.state_digest(ws.incident_id, list(reversed(initial["records"]))) == initial["incident_state_digest"]


@pytest.mark.parametrize("field,value", [
    ("incident_id", "INC-OTHER"), ("audit_head_hash", "0" * 64),
    ("incident_state_digest", "0" * 64), ("created_by", "attacker"),
    ("sequence", 2), ("snapshot_id", "SNP-" + "0" * 64),
    ("signature_algorithm", "none"), ("schema_version", True), ("final", 1),
])
def test_payload_mutations_never_verify(case, field, value):
    ws, key, store = case
    doc = capture(case)
    doc["payload"][field] = value
    assert not s.verify_document(doc, key.verify_key, incident_id=ws.incident_id)["valid"]


def test_bad_signature_wrong_pin_unknown_signer_and_identity(case):
    ws, key, store = case
    doc = capture(case)
    wrong, _ = signing.generate_signing_keypair()
    assert not s.verify_document(doc, wrong.verify_key)["signer_trusted"]
    assert not s.verify_document(doc, None)["valid"]
    assert not s.verify_document(doc, key.verify_key, expected_id="SNP-" + "0" * 64)["valid"]
    assert not s.verify_document(doc, key.verify_key, incident_id="other")["valid"]
    doc["signature"] = base64.b64encode(b"x" * 64).decode()
    result = s.verify_document(doc, key.verify_key)
    assert result["structure_valid"] and not result["signature_valid"]


@pytest.mark.parametrize("source", ["state.json", "observations.json", "claims.json", "actions.json", "decisions.json", "subjects.json", "manifest.json", "audit.jsonl"])
@pytest.mark.parametrize("operation", ["modify", "delete"])
def test_state_tampering_and_deletion_detected(case, tmp_path, source, operation):
    ws, _, store = case
    populate(ws, tmp_path)
    doc = capture(case)
    path = ws.dir / source
    if operation == "delete":
        path.unlink()
    elif source == "audit.jsonl":
        path.write_text(path.read_text().splitlines()[0] + "\n")
    else:
        data = json.loads(path.read_text())
        data["tampered"] = True
        path.write_text(json.dumps(data))
    assert store.verify_snapshot(sid(doc))["valid"]  # Historical authentication survives.
    assert not store.compare_current(sid(doc))["current_state_matches"]


def test_custody_and_logical_records_in_inventory(case, tmp_path):
    ws, _, store = case
    obs, claim, action = populate(ws, tmp_path)
    doc = capture(case)
    types = {r["type"] for r in doc["payload"]["records"]}
    assert {"evidence", "custody-event", "subject", "observation", "claim", "action", "decision", "audit-entry"} <= types
    manifest = json.loads(ws._manifest_path.read_text())
    manifest["custody"][0]["collector"] = "attacker"
    ws._manifest_path.write_text(json.dumps(manifest))
    assert not store.compare_current(sid(doc))["records_match"]


def make_chain(case):
    ws, _, _ = case
    a = capture(case)
    ws.add_observation("B", "analyst")
    b = capture(case)
    ws.add_observation("C", "analyst")
    c = capture(case)
    return a, b, c


@pytest.mark.parametrize("damage", ["delete-middle", "modify-middle", "swap", "duplicate", "predecessor", "malformed"])
def test_chain_corruption(case, damage):
    ws, key, store = case
    a, b, c = make_chain(case)
    assert store.verify_chain()["valid"]
    bp = store.directory / f"{sid(b)}.json"
    cp = store.directory / f"{sid(c)}.json"
    if damage == "delete-middle":
        bp.unlink()
    elif damage == "modify-middle":
        b["signature"] = base64.b64encode(b"x" * 64).decode()
        bp.write_text(json.dumps(b))
    elif damage == "swap":
        bp.write_text(json.dumps(c))
        cp.write_text(json.dumps(b))
    elif damage == "duplicate":
        (store.directory / ("SNP-" + "0" * 64 + ".json")).write_text(json.dumps(b))
    elif damage == "predecessor":
        c["payload"]["previous_snapshot_digest"] = "0" * 64
        c["payload"]["snapshot_id"] = s.snapshot_id(c["payload"])
        c["signature"] = base64.b64encode(signing.sign(s.PREFIX + s.canonical_bytes(c["payload"]), key)).decode()
        cp.unlink()
        (store.directory / f"{sid(c)}.json").write_text(json.dumps(c))
    else:
        cp.write_text("{")
    assert not store.verify_chain()["valid"]
    assert not ws.verify()["ok"]
    with pytest.raises(s.SnapshotError):
        capture(case)


def test_enumeration_order_and_tip_deletion_limits(case, monkeypatch):
    ws, _, store = case
    a, b, c = make_chain(case)
    original = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda p: iter(reversed(list(original(p)))))
    assert store.verify_chain()["valid"]
    (store.directory / f"{sid(c)}.json").unlink()
    assert store.verify_chain()["valid"]  # A pure local chain cannot know C existed.
    assert not store.verify_chain(expected_tip=sid(c))["valid"]
    assert not store.verify_chain(expected_tip=s.snapshot_digest(c))["valid"]


def test_current_legitimate_change_and_rollback(case):
    ws, _, store = case
    a = capture(case)
    saved = {n: (ws.dir / n).read_bytes() for n in s.SOURCES if (ws.dir / n).exists()}
    ws.add_observation("B", "analyst")
    assert not store.compare_current(sid(a))["current_state_matches"]
    assert ws.verify()["ok"]  # An ordinary historical checkpoint may differ.
    b = capture(case)
    ws.add_observation("C", "analyst")
    c = capture(case)
    for name in s.SOURCES:
        path = ws.dir / name
        if name in saved:
            path.write_bytes(saved[name])
        elif path.exists():
            path.unlink()
    assert store.compare_current(sid(a))["current_state_matches"]
    assert not store.compare_current(sid(c))["current_state_matches"]
    assert not ws.verify()["snapshot_health"]["valid"]
    with pytest.raises(s.SnapshotError, match="audit"):
        capture(case)


def test_lifecycle_final_checkpoint_and_required_recovery(case, tmp_path, monkeypatch):
    ws, key, store = case
    assert capture(case)["payload"]["final"] is False  # OPEN
    populate(ws, tmp_path)
    ws.transition("RESOLVED", "analyst")
    capture(case)
    ws.close_incident("analyst")
    capture(case)
    with pytest.raises(WorkspaceError, match="external signing key"):
        ws.seal_incident("analyst")
    ws.seal_incident("analyst", snapshot_signing_key=key)
    assert ws.is_sealed and ws.verify()["ok"]
    final = store.verify_chain()["latest"]
    assert final["payload"]["final"]
    assert store.compare_current(sid(final))["current_state_matches"]
    assert sid(final) in ws.snapshot_report()
    with pytest.raises(WorkspaceError):
        ws.add_observation("forbidden", "analyst")
    with pytest.raises(s.SnapshotError, match="final checkpoint"):
        capture(case)
    (store.directory / f"{sid(final)}.json").unlink()
    assert ws.verify()["snapshot_health"]["status"] == "FINAL_SNAPSHOT_MISSING"
    capture(case)  # Explicit recovery signs existing SEALED state; never rewrites it.
    assert ws.verify()["ok"]
    state = json.loads(ws._state_path.read_text())
    state["title"] = "tampered sealed metadata"
    ws._state_path.write_text(json.dumps(state))
    assert not ws.verify()["ok"]


def test_legacy_sealed_incident_compatibility(case, tmp_path):
    ws, _, store = case
    populate(ws, tmp_path)
    ws.close_incident("analyst")
    ws.seal_incident("analyst")
    assert ws.verify()["snapshot_health"]["status"] == "NOT_PRESENT"
    before = {n: (ws.dir / n).read_bytes() for n in s.SOURCES if (ws.dir / n).exists()}
    doc = capture(case)
    assert doc["payload"]["final"]
    assert ws.verify()["ok"]
    assert all((ws.dir / n).read_bytes() == b for n, b in before.items())


@pytest.mark.parametrize("failure", ["sign", "publish"])
def test_failed_creation_never_rewrites_authoritative_history(case, monkeypatch, failure):
    ws, _, store = case
    before = files(ws.dir)
    def fail(*args, **kwargs):
        raise RuntimeError("SYNTHETIC_PRIVATE_KEY_MUST_NOT_LEAK")
    monkeypatch.setattr(signing if failure == "sign" else s, "sign" if failure == "sign" else "_publish", fail)
    with pytest.raises(s.SnapshotError) as error:
        capture(case)
    assert "SYNTHETIC_PRIVATE_KEY" not in str(error.value)
    assert files(ws.dir) == before


def test_atomic_publication_failure_and_no_overwrite(case, monkeypatch):
    ws, _, store = case
    def fail(*args, **kwargs):
        raise OSError("injected link failure")
    with monkeypatch.context() as m:
        m.setattr(s.os, "link", fail)
        with pytest.raises(s.SnapshotError):
            capture(case)
    assert list(store.directory.iterdir()) == []
    doc = capture(case)
    path = store.directory / f"{sid(doc)}.json"
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        s._publish(path, b"replacement")
    assert path.read_bytes() == original


def test_seal_signing_failure_is_detectable_and_recoverable(case, tmp_path, monkeypatch):
    ws, key, store = case
    populate(ws, tmp_path)
    capture(case)
    ws.close_incident("analyst")
    with monkeypatch.context() as m:
        m.setattr(s, "_publish", lambda *a, **kw: (_ for _ in ()).throw(OSError()))
        with pytest.raises(WorkspaceError, match="final snapshot missing"):
            ws.seal_incident("analyst", snapshot_signing_key=key)
    assert ws.is_sealed and not ws.verify()["ok"]
    capture(case)
    assert ws.verify()["ok"]


@pytest.mark.parametrize("path", ["../../state", "/tmp/elsewhere", "SNP-../x", "", "SNP-" + "g" * 64])
def test_untrusted_snapshot_ids_never_access_paths(case, path):
    _, _, store = case
    assert not store.verify_snapshot(path)["valid"]


@pytest.mark.parametrize("source", ["state.json", "observations.json", "snapshots", ".coreline.lock"])
def test_symlinks_rejected_before_creation(case, tmp_path, source):
    ws, _, store = case
    target = tmp_path / "outside"
    path = ws.dir / source
    if path.exists():
        target.write_bytes(path.read_bytes())
        path.unlink()
    else:
        target.write_text("{}")
    path.symlink_to(target)
    before = target.read_bytes()
    with pytest.raises(s.SnapshotError):
        capture(case)
    assert target.read_bytes() == before


def test_duplicate_json_keys_and_malformed_corpus(case):
    _, key, store = case
    doc = capture(case)
    path = store.directory / f"{sid(doc)}.json"
    for raw in [b"{", b"[]", b"null", b'{"payload":{},"payload":{}}', b'{"x":NaN}', b'"x"', b'\xff']:
        path.write_bytes(raw)
        assert not store.verify_snapshot(sid(doc))["valid"]
        assert not store.verify_chain()["valid"]
    for value in [None, [], "", 1, True, {"payload": {}}, {"payload": [], "signature": "x"}]:
        assert not s.verify_document(value, key.verify_key)["valid"]


def test_canonicalization_permutation_corpus():
    rng = random.Random(713)
    value = {"z": [1, 2], "unicode": "é", "a": {"b": True, "a": None}}
    expected = s.canonical_bytes(value)
    for _ in range(100):
        pairs = list(value.items())
        rng.shuffle(pairs)
        assert s.canonical_bytes(dict(pairs)) == expected
    assert s.canonical_bytes({**value, "a": 2}) != expected
    with pytest.raises(ValueError):
        s.canonical_bytes({"x": float("nan")})


def test_keys_missing_invalid_external_and_unknown(case, tmp_path):
    ws, key, store = case
    with pytest.raises(s.SnapshotError):
        s.load_private_key(ws._key_path, ws.home)
    for data in (b"invalid", b"", base64.b64encode(b"short")):
        path = tmp_path / "bad.key"
        path.write_bytes(data)
        with pytest.raises(s.SnapshotError):
            s.load_private_key(path, ws.home)
    with pytest.raises(s.SnapshotError):
        s.load_private_key(tmp_path / "missing", ws.home)
    with pytest.raises(s.SnapshotError):
        s.generate_key_files(ws.home, ws.dir / "private.key", tmp_path / "pin.json")
    wrong, _ = signing.generate_signing_keypair()
    with pytest.raises(s.SnapshotError, match="public pin"):
        store.create(wrong, "analyst")
    doc = capture(case)
    (ws.home / "trust" / "snapshot.verify.json").unlink()
    assert not s.SnapshotStore(ws).verify_snapshot(sid(doc))["valid"]
    assert s.SnapshotStore(ws, key.verify_key).verify_snapshot(sid(doc))["valid"]


def test_added_empty_store_and_refusal_to_capture_corruption(case):
    ws, _, store = case
    doc = capture(case)
    ws._observations_path.write_text(json.dumps({"version": "1", "incident_id": ws.incident_id, "observations": [], "amendments": []}))
    result = store.compare_current(sid(doc))
    assert result["records_match"] and not result["current_state_matches"] and result["added"]
    ws._audit_path.write_text("{}\n")
    with pytest.raises(s.SnapshotError):
        capture(case)


def test_inventory_does_not_read_evidence_bytes(case, tmp_path, monkeypatch):
    ws, _, _ = case
    populate(ws, tmp_path)
    monkeypatch.setattr("core.incident.workspace.sha256_file", lambda *a: pytest.fail("inventory read artifact"))
    assert s.inventory(ws)["incident_state_digest"]


def test_snapshot_contains_no_private_material_or_absolute_paths(case, tmp_path):
    ws, key, store = case
    populate(ws, tmp_path)
    doc = capture(case)
    encoded = json.dumps(doc)
    assert str(tmp_path) not in encoded
    assert base64.b64encode(signing.encode_signing_key(key)).decode() not in encoded
    assert "verify_key" not in doc
    assert all(r["source"] in s.SOURCES for r in doc["payload"]["records"])


def test_unreadable_snapshot_and_symlinked_live_source_fail_health(case, tmp_path, monkeypatch):
    ws, _, store = case
    doc = capture(case)
    original = s._read
    with monkeypatch.context() as m:
        def unreadable(path):
            if path.parent == store.directory:
                raise PermissionError("synthetic private information")
            return original(path)
        m.setattr(s, "_read", unreadable)
        assert not store.verify_snapshot(sid(doc))["valid"]
        assert not store.verify_chain()["valid"]
    destination = tmp_path / "moved-state"
    ws._state_path.rename(destination)
    ws._state_path.symlink_to(destination)
    assert not store.health()["valid"]
    assert not ws.verify()["ok"]


def test_snapshot_sources_never_follow_signed_arbitrary_paths(case):
    ws, key, store = case
    doc = capture(case)
    doc["payload"]["records"][0]["source"] = "../../outside"
    doc["payload"]["incident_state_digest"] = s.state_digest(ws.incident_id, doc["payload"]["records"])
    doc["payload"]["snapshot_id"] = s.snapshot_id(doc["payload"])
    doc["signature"] = base64.b64encode(signing.sign(s.PREFIX + s.canonical_bytes(doc["payload"]), key)).decode()
    assert not s.verify_document(doc, key.verify_key)["structure_valid"]


def test_independent_pin_defeats_local_key_and_snapshot_substitution(case):
    ws, key, store = case
    doc = capture(case)
    attacker, _ = signing.generate_signing_keypair()
    doc["payload"]["signing_key_id"] = signing.key_fingerprint(attacker.verify_key)
    doc["payload"]["snapshot_id"] = s.snapshot_id(doc["payload"])
    doc["signature"] = base64.b64encode(signing.sign(s.PREFIX + s.canonical_bytes(doc["payload"]), attacker)).decode()
    assert not s.verify_document(doc, key.verify_key)["valid"]
    # Trusting the substituted key would work: trust must be independently pinned.
    assert s.verify_document(doc, attacker.verify_key)["valid"]


def test_missing_all_required_final_snapshots_fails(case, tmp_path):
    ws, key, store = case
    populate(ws, tmp_path)
    ws.close_incident("analyst")
    ws.seal_incident("analyst", snapshot_signing_key=key)
    for path in store.directory.iterdir():
        path.unlink()
    assert store.health()["status"] == "FINAL_SNAPSHOT_MISSING"
    assert not ws.verify()["ok"]


@pytest.mark.parametrize("tip", ["", "garbage", "../escape", [], 1])
def test_malformed_expected_tip_fails_predictably(case, tip):
    _, _, store = case
    capture(case)
    assert not store.verify_chain(tip)["valid"]


def test_private_key_permissions_and_duplicate_source_json(case):
    ws, _, store = case
    private = ws.home.parent / "external" / "snapshot.key"
    assert private.stat().st_mode & 0o777 == 0o600
    text = ws._state_path.read_text()
    ws._state_path.write_text(text.replace('{', '{"incident_id":"duplicate",', 1))
    with pytest.raises(s.SnapshotError):
        capture(case)


def test_process_restart_and_concurrent_creation(case):
    ws, _, store = case
    expected = s.inventory(ws)["incident_state_digest"]
    code = "from pathlib import Path; from core.incident import IncidentWorkspace; from core.incident.snapshots import inventory; import sys; print(inventory(IncidentWorkspace.load(Path(sys.argv[1]), sys.argv[2]))['incident_state_digest'])"
    repository = Path(__file__).resolve().parents[3]
    result = subprocess.run([sys.executable, "-c", code, str(ws.home), ws.incident_id], cwd=repository, capture_output=True, text=True, check=True, timeout=20)
    assert result.stdout.strip() == expected
    code = "from pathlib import Path; from core.incident import IncidentWorkspace; from core.incident.snapshots import SnapshotStore, load_private_key; import sys; ws=IncidentWorkspace.load(Path(sys.argv[1]), sys.argv[2]); SnapshotStore(ws).create(load_private_key(sys.argv[3], ws.home), 'concurrent')"
    args = [sys.executable, "-c", code, str(ws.home), ws.incident_id, str(ws.home.parent / "external" / "snapshot.key")]
    processes = [subprocess.Popen(args, cwd=repository, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
    try:
        for process in processes:
            process.communicate(timeout=20)
            assert process.returncode == 0
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()
    chain = store.verify_chain()
    assert chain["valid"] and chain["count"] == 2
    assert s.inventory(ws)["incident_state_digest"] == expected


@pytest.mark.parametrize("kind,field", [("observations", "text"), ("claims", "text"), ("actions", "description"), ("decisions", "statement"), ("subjects", "value")])
def test_individual_record_changes_are_identified(case, tmp_path, kind, field):
    ws, _, store = case
    populate(ws, tmp_path)
    doc = capture(case)
    path = ws.dir / f"{kind}.json"
    data = json.loads(path.read_text())
    assert field in data[kind][0]
    data[kind][0][field] = "modified"
    path.write_text(json.dumps(data))
    result = store.compare_current(sid(doc))
    assert not result["current_state_matches"]
    assert any(key[1] == kind[:-1] for key in result["modified"])


def test_amendments_are_captured_and_order_independent(case, tmp_path):
    ws, _, store = case
    obs, claim, action = populate(ws, tmp_path)
    decision = ws.decisions()[0]
    ws.correct_observation(obs.observation_id, "correction", "analyst")
    ws.correct_observation(obs.observation_id, "second correction", "analyst")
    ws.correct_claim(claim.claim_id, "correction", "analyst")
    ws.amend_action(action.action_id, "correction", "analyst")
    ws.amend_decision(decision.decision_id, "correction", "analyst")
    doc = capture(case)
    types = {r["type"] for r in doc["payload"]["records"]}
    assert {"observation-amendment", "claim-amendment", "action-amendment", "decision-amendment"} <= types
    path = ws._observations_path
    data = json.loads(path.read_text())
    data["amendments"].reverse()
    path.write_text(json.dumps(data))
    assert store.compare_current(sid(doc))["current_state_matches"]
    data["amendments"].pop()
    path.write_text(json.dumps(data))
    result = store.compare_current(sid(doc))
    assert not result["current_state_matches"]
    assert any(key[1] == "observation-amendment" for key in result["missing"])


def test_key_symlink_loop_fails_without_raw_errors(case, tmp_path, monkeypatch):
    ws, _, store = case
    doc = capture(case)
    loop = tmp_path / "CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91"
    loop.symlink_to(loop)
    monkeypatch.setenv("CORELINE_SNAPSHOT_VERIFY_KEY", str(loop))
    assert not ws.verify()["ok"]
    assert not s.SnapshotStore(ws).verify_snapshot(sid(doc))["valid"]
    for loader, args in [(s.load_public_key, (loop,)), (s.load_private_key, (loop, ws.home))]:
        with pytest.raises(s.SnapshotError) as error:
            loader(*args)
        assert loop.name not in str(error.value)


@pytest.mark.parametrize("field,value", [("algorithm", "rsa"), ("verify_key", "!invalid!"), ("fingerprint", "wrong")])
def test_malformed_public_pin_fails(case, field, value):
    ws, _, store = case
    capture(case)
    pin = ws.home / "trust" / "snapshot.verify.json"
    data = json.loads(pin.read_text())
    data[field] = value
    pin.write_text(json.dumps(data))
    with pytest.raises(s.SnapshotError):
        s.load_public_key(pin)
    assert not ws.verify()["ok"]
