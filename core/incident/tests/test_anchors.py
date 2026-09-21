"""Adversarial tests for independent snapshot receipt ledgers and policy."""
import base64
import copy
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.evidence.integrity import signing
from core.incident import IncidentWorkspace, WorkspaceError
from core.incident import anchors as a
from core.incident import snapshots as s

WHEN = datetime(2026, 9, 20, 18, 0, tzinfo=timezone.utc)


@pytest.fixture
def anchored(tmp_path, monkeypatch):
    monkeypatch.delenv("CORELINE_ANCHOR_REGISTRY", raising=False)
    monkeypatch.delenv("CORELINE_SNAPSHOT_VERIFY_KEY", raising=False)
    ws = IncidentWorkspace.declare(tmp_path / "home", title="Anchor test", severity="SEV2", actor="analyst")
    snapshot_private = tmp_path / "snapshot.key"
    s.generate_key_files(ws.home, snapshot_private, ws.home / "trust" / "snapshot.verify.json")
    snapshot_key = s.load_private_key(snapshot_private, ws.home)
    anchor_key, anchor_public = signing.generate_signing_keypair()
    anchor_root = tmp_path / "independent-anchor"
    a.write_registry(a.registry_path(ws.home), "vault-a", anchor_root, anchor_public, "OPTIONAL")
    config = a.load_registry(a.registry_path(ws.home), incident_dir=ws.dir)
    manager = a.AnchorManager(ws, config, snapshot_key.verify_key)
    return ws, snapshot_key, anchor_key, anchor_root, config, manager


def snapshot(case):
    ws, snapshot_key, *_ = case
    return ws.create_snapshot(snapshot_key, "analyst", when=WHEN)


def anchor(case, document):
    ws, _, anchor_key, _, config, manager = case
    return manager.anchor_snapshot(document["payload"]["snapshot_id"], anchor_key, WHEN)


def set_policy(case, policy):
    ws, _, _, _, config, _ = case
    config["anchors"]["vault-a"]["policy"] = policy
    return a.AnchorManager(ws, config, case[1].verify_key)


def chain(case, count=3, anchored_count=None):
    ws = case[0]
    docs, receipts = [], []
    for index in range(count):
        if index:
            ws.add_observation(f"state {index + 1}", "analyst")
        doc = snapshot(case)
        docs.append(doc)
        if anchored_count is None or index < anchored_count:
            receipts.append(anchor(case, doc))
    return docs, receipts


def test_request_minimal_deterministic_and_content_free(anchored):
    ws, *_ = anchored
    ws.add_observation("PII SHOULD NOT CROSS BOUNDARY", "analyst")
    doc = snapshot(anchored)
    request = a.request_from_snapshot(doc)
    assert set(request) == a.REQUEST_FIELDS
    assert a.canonical_bytes(dict(reversed(list(request.items())))) == a.canonical_bytes(request)
    assert "PII SHOULD NOT CROSS BOUNDARY" not in json.dumps(request)
    receipt = anchor(anchored, doc)
    assert "PII SHOULD NOT CROSS BOUNDARY" not in json.dumps(receipt)


@pytest.mark.parametrize("field,value", [
    ("incident_id", "INC-WRONG"), ("snapshot_id", "SNP-" + "0" * 64),
    ("snapshot_digest", "0" * 64), ("state_digest", "0" * 64),
    ("anchor_id", "other"), ("anchor_sequence", 9),
    ("snapshot_sequence", 9), ("previous_snapshot_digest", "0" * 64),
    ("previous_receipt_digest", "0" * 64), ("receipt_id", "ANC-" + "0" * 64),
    ("authentication_algorithm", "snapshot-ed25519"),
])
def test_receipt_mutations_fail_authentication(anchored, field, value):
    receipt = anchor(anchored, snapshot(anchored))
    receipt["payload"][field] = value
    result = a.verify_receipt(receipt, anchored[2].verify_key, anchor_id="vault-a",
                              incident_id=anchored[0].incident_id)
    assert not result["valid"]


def test_wrong_key_embedded_key_and_cross_protocol_signatures_fail(anchored):
    receipt = anchor(anchored, snapshot(anchored))
    attacker, _ = signing.generate_signing_keypair()
    assert not a.verify_receipt(receipt, attacker.verify_key)["valid"]
    receipt["verify_key"] = signing.encode_verify_key(attacker.verify_key)
    assert not a.verify_receipt(receipt, attacker.verify_key)["valid"]
    original = anchor(anchored, anchored[5].ws.verify_snapshot_chain()["latest"])
    # Snapshot-domain signatures cannot authenticate anchor-domain payloads.
    original["signature"] = base64.b64encode(signing.sign(s.PREFIX + a.canonical_bytes(original["payload"]), anchored[2])).decode()
    assert not a.verify_receipt(original, anchored[2].verify_key)["valid"]


@pytest.mark.parametrize("bad", [None, [], {}, {"payload": {}}, {"payload": [], "signature": "x"}, "x", 1])
def test_malformed_receipts_never_raise(anchored, bad):
    assert not a.verify_receipt(bad, anchored[2].verify_key)["valid"]


def test_signed_receipt_and_ledger_links(anchored):
    docs, receipts = chain(anchored)
    provider = anchored[5].provider()
    ledger = provider.verify_ledger(anchored[0].incident_id)
    assert ledger["valid"] and ledger["count"] == 3
    for index, receipt in enumerate(receipts):
        assert receipt["payload"]["snapshot_id"] == docs[index]["payload"]["snapshot_id"]
        assert receipt["payload"]["anchor_sequence"] == index + 1
        if index:
            assert receipt["payload"]["previous_receipt_digest"] == a.receipt_digest(receipts[index - 1])


def test_duplicate_is_idempotent_rollback_skip_and_divergence_rejected(anchored):
    docs, receipts = chain(anchored, 3, 1)
    duplicate = anchor(anchored, docs[0])
    assert duplicate == receipts[0]
    with pytest.raises(a.AnchorError, match="sequentially"):
        anchor(anchored, docs[2])
    anchor(anchored, docs[1])
    with pytest.raises(a.AnchorError):
        anchor(anchored, docs[0])
    bad = a.request_from_snapshot(docs[2])
    bad["previous_snapshot_digest"] = "0" * 64
    with pytest.raises(a.AnchorError):
        anchored[5].provider(anchored[2]).anchor(bad)


@pytest.mark.parametrize("damage", ["delete-middle", "modify", "replace", "malformed", "extra"])
def test_external_ledger_damage_fails_closed(anchored, damage):
    _, receipts = chain(anchored)
    provider = anchored[5].provider()
    directory = provider._incident_dir(anchored[0].incident_id)
    second = directory / f"{receipts[1]['payload']['receipt_id']}.json"
    if damage == "delete-middle":
        second.unlink()
    elif damage == "modify":
        value = json.loads(second.read_text()); value["payload"]["state_digest"] = "0" * 64
        second.write_text(json.dumps(value))
    elif damage == "replace":
        second.write_text(json.dumps(receipts[0]))
    elif damage == "malformed":
        second.write_text("{")
    else:
        (directory / "untrusted.json").write_text("{}")
    assert not provider.verify_ledger(anchored[0].incident_id)["valid"]
    assert not anchored[5].health()["valid"]


def test_expected_tip_relations_and_policy(anchored):
    docs, _ = chain(anchored, 1)
    assert anchored[5].health()["expected_tip_relation"] == "MATCH"
    anchored[0].add_observation("new", "analyst"); second = snapshot(anchored)
    health = anchored[5].health()
    assert health["valid"] and health["expected_tip_relation"] == "LOCAL_AHEAD_OF_EXPECTED"
    required = set_policy(anchored, "REQUIRED")
    assert not required.health()["valid"]
    anchor(anchored, second)
    assert required.health()["valid"] and required.health()["expected_tip_relation"] == "MATCH"


def test_independent_tip_detects_local_rollback_and_deletion(anchored):
    docs, _ = chain(anchored)
    directory = anchored[0].dir / "snapshots"
    cache = anchored[0].dir / "anchors" / "vault-a"
    for index, expected in [(2, "LOCAL_BEHIND_EXPECTED"), (1, "LOCAL_BEHIND_EXPECTED")]:
        for doc in docs[index:]:
            path = directory / f"{doc['payload']['snapshot_id']}.json"
            if path.exists(): path.unlink()
        for path in list(cache.glob("*.json")):
            path.unlink()
        health = anchored[5].health()
        assert not health["valid"] and health["expected_tip_relation"] == expected
    for path in directory.glob("*.json"):
        path.unlink()
    assert anchored[5].health()["expected_tip_relation"] == "LOCAL_SNAPSHOTS_MISSING"


def test_diverged_valid_local_chain_detected(anchored):
    docs, _ = chain(anchored)
    third = copy.deepcopy(docs[2])
    third["payload"]["created_by"] = "alternate"
    third["payload"]["snapshot_id"] = s.snapshot_id(third["payload"])
    third["signature"] = base64.b64encode(signing.sign(s.PREFIX + s.canonical_bytes(third["payload"]), anchored[1])).decode()
    directory = anchored[0].dir / "snapshots"
    (directory / f"{docs[2]['payload']['snapshot_id']}.json").unlink()
    (directory / f"{third['payload']['snapshot_id']}.json").write_bytes(s.canonical_bytes(third))
    assert anchored[5].health()["expected_tip_relation"] == "DIVERGED"


def test_offline_receipt_authenticity_is_not_freshness(anchored):
    anchor(anchored, snapshot(anchored))
    offline = a.AnchorManager(anchored[0], anchored[4], anchored[1].verify_key, online=False).health()
    assert offline["valid"] and offline["receipt_authentic"]
    assert not offline["expected_tip_checked"] and offline["status"] == "OFFLINE_RECEIPT_VERIFIED"
    required = set_policy(anchored, "REQUIRED")
    required.online = False
    assert not required.health()["valid"]


def test_optional_missing_valid_invalid_and_unavailable(anchored, monkeypatch):
    assert anchored[5].health()["valid"] and anchored[5].health()["status"] == "UNANCHORED"
    doc = snapshot(anchored); receipt = anchor(anchored, doc)
    cached = anchored[5].cache_dir / f"{receipt['payload']['receipt_id']}.json"
    value = json.loads(cached.read_text()); value["signature"] = base64.b64encode(b"x" * 64).decode()
    cached.write_text(json.dumps(value))
    assert not anchored[5].health()["valid"]
    cached.write_bytes(a.canonical_bytes(receipt))
    monkeypatch.setattr(a.FilesystemAnchor, "get_expected_tip", lambda *x: (_ for _ in ()).throw(a.AnchorUnavailable()))
    health = anchored[5].health()
    assert health["valid"] and not health["expected_tip_checked"] and health["receipt_authentic"]


def test_required_unavailable_never_downgrades(anchored, monkeypatch):
    doc = snapshot(anchored); anchor(anchored, doc)
    manager = set_policy(anchored, "REQUIRED")
    monkeypatch.setattr(a.FilesystemAnchor, "get_expected_tip", lambda *x: (_ for _ in ()).throw(a.AnchorUnavailable()))
    assert not manager.health()["valid"] and not manager.health()["anchor_policy_satisfied"]


def test_required_external_ledger_disappearance_fails_even_with_cache(anchored):
    doc = snapshot(anchored); anchor(anchored, doc)
    manager = set_policy(anchored, "REQUIRED")
    directory = manager.provider()._incident_dir(anchored[0].incident_id)
    for path in directory.glob("*.json"):
        path.unlink()
    assert not manager.health()["valid"]
    assert not manager.health()["expected_tip_available"]


def test_optional_detects_external_expected_tip_rollback_against_cache(anchored):
    docs, receipts = chain(anchored)
    directory = anchored[5].provider()._incident_dir(anchored[0].incident_id)
    (directory / f"{receipts[2]['payload']['receipt_id']}.json").unlink()
    health = anchored[5].health()
    assert not health["valid"] and health["status"] == "INVALID"
    (directory / f"{receipts[1]['payload']['receipt_id']}.json").unlink()
    (directory / f"{receipts[0]['payload']['receipt_id']}.json").unlink()
    health = anchored[5].health()
    assert not health["valid"] and health["status"] == "INVALID"


@pytest.mark.parametrize("anchor_id", ["../escape", "/absolute", "", "x/y", "a" * 65])
def test_malicious_anchor_identity_rejected(anchored, anchor_id):
    with pytest.raises(a.AnchorError):
        a.FilesystemAnchor(anchored[3], anchor_id, anchored[2].verify_key)


@pytest.mark.parametrize("change", ["shape", "incident", "snapshot", "sequence", "nan"])
def test_malformed_anchor_requests_rejected(anchored, change):
    request = a.request_from_snapshot(snapshot(anchored))
    if change == "shape": request["extra"] = True
    elif change == "incident": request["incident_id"] = ""
    elif change == "snapshot": request["snapshot_id"] = "../../state"
    elif change == "sequence": request["snapshot_sequence"] = True
    else: request["state_digest"] = float("nan")
    with pytest.raises(a.AnchorError):
        anchored[5].provider(anchored[2]).anchor(request)


def test_required_for_seal_success_and_recoverable_failure(anchored, tmp_path, monkeypatch):
    ws, snapshot_key, anchor_key, _, config, _ = anchored
    config["anchors"]["vault-a"]["policy"] = "REQUIRED_FOR_SEAL"
    artifact = tmp_path / "evidence"; artifact.write_text("preserved")
    ws.add_evidence(str(artifact), "test", "analyst")
    first = snapshot(anchored); a.AnchorManager(ws, config, snapshot_key.verify_key).anchor_snapshot(first["payload"]["snapshot_id"], anchor_key)
    ws.close_incident("analyst")
    with pytest.raises(WorkspaceError, match="anchor signing key"):
        ws.seal_incident("analyst", snapshot_signing_key=snapshot_key,
                         snapshot_verify_key=snapshot_key.verify_key, anchor_config=config)
    assert not ws.is_sealed
    with monkeypatch.context() as scoped:
        scoped.setattr(a.FilesystemAnchor, "anchor", lambda *args, **kwargs: (_ for _ in ()).throw(a.AnchorUnavailable()))
        with pytest.raises(WorkspaceError, match="required final anchor"):
            ws.seal_incident("analyst", snapshot_signing_key=snapshot_key,
                             snapshot_verify_key=snapshot_key.verify_key, anchor_config=config,
                             anchor_signing_key=anchor_key)
    assert ws.is_sealed
    final = s.SnapshotStore(ws, snapshot_key.verify_key).verify_chain()["latest"]
    manager = a.AnchorManager(ws, config, snapshot_key.verify_key)
    manager.anchor_snapshot(final["payload"]["snapshot_id"], anchor_key)
    assert manager.health()["valid"] and ws.verify(snapshot_verify_key=snapshot_key.verify_key,
                                                    anchor_config=config)["ok"]


def test_required_for_seal_one_operation_success(anchored, tmp_path):
    ws, snapshot_key, anchor_key, _, config, _ = anchored
    config["anchors"]["vault-a"]["policy"] = "REQUIRED_FOR_SEAL"
    artifact = tmp_path / "evidence"; artifact.write_text("preserved")
    ws.add_evidence(str(artifact), "test", "analyst")
    first = snapshot(anchored); a.AnchorManager(ws, config, snapshot_key.verify_key).anchor_snapshot(first["payload"]["snapshot_id"], anchor_key)
    ws.close_incident("analyst")
    ws.seal_incident("analyst", snapshot_signing_key=snapshot_key,
                     snapshot_verify_key=snapshot_key.verify_key, anchor_config=config,
                     anchor_signing_key=anchor_key)
    assert ws.verify(snapshot_verify_key=snapshot_key.verify_key, anchor_config=config)["ok"]


def test_required_policy_anchors_final_snapshot_during_seal(anchored, tmp_path):
    ws, snapshot_key, anchor_key, _, config, manager = anchored
    config["anchors"]["vault-a"]["policy"] = "REQUIRED"
    artifact = tmp_path / "required-evidence"; artifact.write_text("preserved")
    ws.add_evidence(str(artifact), "test", "analyst")
    first = snapshot(anchored); manager.anchor_snapshot(first["payload"]["snapshot_id"], anchor_key)
    ws.close_incident("analyst")
    with pytest.raises(WorkspaceError, match="anchor signing key"):
        ws.seal_incident("analyst", snapshot_signing_key=snapshot_key,
                         snapshot_verify_key=snapshot_key.verify_key, anchor_config=config)
    ws.seal_incident("analyst", snapshot_signing_key=snapshot_key,
                     snapshot_verify_key=snapshot_key.verify_key, anchor_config=config,
                     anchor_signing_key=anchor_key)
    assert manager.health()["expected_tip_relation"] == "MATCH"


def test_external_success_local_cache_failure_is_idempotently_recoverable(anchored, monkeypatch):
    doc = snapshot(anchored)
    original = a._publish
    def fail_cache(path, data, mode=0o600):
        if str(path).startswith(str(anchored[0].dir)):
            raise OSError("CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91")
        return original(path, data, mode)
    with monkeypatch.context() as scoped:
        scoped.setattr(a, "_publish", fail_cache)
        with pytest.raises(a.AnchorError) as error:
            anchor(anchored, doc)
        assert "CORELINE_TEST_SECRET" not in str(error.value)
    receipt = anchor(anchored, doc)
    assert receipt["payload"]["snapshot_id"] == doc["payload"]["snapshot_id"]
    assert anchored[5].health()["valid"]


@pytest.mark.parametrize("target", ["root", "ledger", "receipt"])
def test_symlinked_anchor_paths_fail_without_touching_target(anchored, tmp_path, target):
    doc = snapshot(anchored)
    root = anchored[3]
    outside = tmp_path / "outside"; outside.mkdir()
    if target == "root":
        root.symlink_to(outside, target_is_directory=True)
    elif target == "ledger":
        root.mkdir(); (root / "ledger").symlink_to(outside, target_is_directory=True)
    else:
        receipt = anchor(anchored, doc)
        path = anchored[5].provider()._incident_dir(anchored[0].incident_id) / f"{receipt['payload']['receipt_id']}.json"
        data = path.read_bytes(); path.unlink(); outside_file = outside / "receipt"; outside_file.write_bytes(data); path.symlink_to(outside_file)
    before = {p.name: p.read_bytes() for p in outside.rglob("*") if p.is_file()}
    assert not anchored[5].provider().verify_ledger(anchored[0].incident_id)["valid"]
    assert {p.name: p.read_bytes() for p in outside.rglob("*") if p.is_file()} == before


def test_cross_incident_receipt_and_cache_substitution(anchored, tmp_path):
    receipt = anchor(anchored, snapshot(anchored))
    other = IncidentWorkspace.declare(tmp_path / "other-home", title="Other", severity="SEV2", actor="analyst")
    other_config = anchored[4]
    other_manager = a.AnchorManager(other, other_config, anchored[1].verify_key, online=False)
    other_manager.cache_dir.mkdir(parents=True)
    (other_manager.cache_dir / f"{receipt['payload']['receipt_id']}.json").write_bytes(a.canonical_bytes(receipt))
    assert not other_manager.health()["valid"]
    assert not a.verify_receipt(receipt, anchored[2].verify_key, incident_id=other.incident_id)["valid"]


def test_malformed_registry_and_untrusted_cached_receipts_fail(anchored):
    path = a.registry_path(anchored[0].home)
    path.write_text("{")
    assert not a.AnchorManager(anchored[0], snapshot_verify_key=anchored[1].verify_key).health()["valid"]


def test_concurrent_duplicate_anchor_is_safe(anchored):
    doc = snapshot(anchored)
    key_path = anchored[0].home.parent / "anchor-process.key"
    key_path.write_bytes(base64.b64encode(signing.encode_signing_key(anchored[2])))
    code = ("from pathlib import Path; import sys; from core.incident import IncidentWorkspace; "
            "from core.incident.anchors import AnchorManager,load_registry; from core.incident.snapshots import load_private_key; "
            "ws=IncidentWorkspace.load(Path(sys.argv[1]),sys.argv[2]); c=load_registry(sys.argv[4],incident_dir=ws.dir); "
            "AnchorManager(ws,c).anchor_snapshot(sys.argv[3],load_private_key(sys.argv[5],ws.home))")
    repo = Path(__file__).resolve().parents[3]
    args = [sys.executable, "-c", code, str(anchored[0].home), anchored[0].incident_id,
            doc["payload"]["snapshot_id"], str(a.registry_path(anchored[0].home)), str(key_path)]
    processes = [subprocess.Popen(args, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
    for process in processes:
        process.communicate(timeout=20)
        assert process.returncode == 0
    assert anchored[5].provider().verify_ledger(anchored[0].incident_id)["count"] == 1


def test_anchor_verification_is_read_only(anchored):
    anchor(anchored, snapshot(anchored))
    before = {str(p.relative_to(anchored[0].home)): (p.read_bytes(), p.stat().st_mtime_ns)
              for p in anchored[0].home.rglob("*") if p.is_file()}
    assert anchored[5].health()["valid"]
    assert anchored[0].anchor_report(anchor_config=anchored[4], snapshot_verify_key=anchored[1].verify_key)
    after = {str(p.relative_to(anchored[0].home)): (p.read_bytes(), p.stat().st_mtime_ns)
             for p in anchored[0].home.rglob("*") if p.is_file()}
    assert before == after
