"""Adversarial tests for signed trust-registry releases and key lifecycle."""
import base64
import copy
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from core.evidence.integrity import signing
from core.incident import IncidentWorkspace
from core.incident import snapshots as s
from core.incident import anchors as a
from core.incident import trust_registry as t
from core.incident.gcs_anchor import GCSAnchor
from core.incident.tests.test_gcs_anchor import FakeGCS

WHEN = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def registry(tmp_path, monkeypatch):
    home = tmp_path / "home"; home.mkdir()
    expected = tmp_path / "independent-tip"
    monkeypatch.setenv("CORELINE_TRUST_EXPECTED_TIP", str(expected))
    root_private, root_public = signing.generate_signing_keypair()
    t.write_root_pin(t.root_path(home), "org-coreline", root_public)
    store = t.TrustRegistryStore(t.releases_path(home), t.load_root_pin(t.root_path(home)), expected)
    first = store.create_release(root_private, "security", [], kind="BOOTSTRAP", when=WHEN)
    return home, store, root_private, root_public, first, expected


def add_key(case, private, purpose="SNAPSHOT_SIGNER", scope="default", identity="snapshot-a"):
    _, store, root, *_ = case
    generation = store.verify_chain()["count"] + 1
    keys = store.latest_keys() + [t.make_key_record(private.verify_key, purpose, scope, identity, generation)]
    return store.create_release(root, "security", keys, when=WHEN)


def test_valid_release_chain_and_expected_tip(registry):
    snapshot, _ = signing.generate_signing_keypair()
    release = add_key(registry, snapshot)
    chain = registry[1].verify_chain(); tip = registry[1].expected_tip()
    assert chain["valid"] and chain["count"] == 2 and chain["latest"] == release
    assert tip["valid"] and tip["relation"] == "MATCH"
    assert registry[1].health(require_expected=True)["valid"]


def test_root_pin_persists_expected_tip_configuration(tmp_path, monkeypatch):
    monkeypatch.delenv("CORELINE_TRUST_EXPECTED_TIP", raising=False)
    home = tmp_path / "home"; expected = tmp_path / "external-tip"
    _, public = signing.generate_signing_keypair()
    t.write_root_pin(t.root_path(home), "org", public, expected)
    discovered = t.TrustRegistryStore.discover(home)
    assert discovered.expected_dir == expected.resolve()


@pytest.mark.parametrize("field,value", [
    ("registry_id", "attacker"), ("generation", 9), ("root_key_id", "SHA256:" + "0" * 64),
    ("previous_release_digest", "0" * 64), ("release_id", "TRR-" + "0" * 64),
])
def test_modified_release_fails(field, value, registry):
    doc = copy.deepcopy(registry[4]); doc["payload"][field] = value
    assert not t.verify_release(doc, registry[3], registry_id="org-coreline")["valid"]


def test_wrong_root_and_self_signed_attacker_fail(registry):
    attacker, attacker_public = signing.generate_signing_keypair()
    assert not t.verify_release(registry[4], attacker_public)["valid"]
    fake = copy.deepcopy(registry[4]); fake["payload"]["root_key_id"] = signing.key_fingerprint(attacker_public)
    fake["payload"]["release_id"] = t.release_id(fake["payload"])
    fake["signature"] = base64.b64encode(signing.sign(t.PREFIX + t.canonical_bytes(fake["payload"]), attacker)).decode()
    assert not t.verify_release(fake, registry[3], registry_id="org-coreline")["valid"]


def test_missing_reordered_duplicate_and_conflicting_generations_fail(registry):
    k1, _ = signing.generate_signing_keypair(); add_key(registry, k1)
    k2, _ = signing.generate_signing_keypair(); add_key(
        registry, k2, purpose="ANCHOR_SIGNER", scope="vault-b", identity="anchor-b")
    paths = registry[1]._paths(); middle = next(p for p in paths if registry[1].read(p.stem)["payload"]["generation"] == 2)
    saved = middle.read_bytes(); middle.unlink()
    assert not registry[1].verify_chain()["valid"]
    middle.write_bytes(saved)
    latest = registry[1].verify_chain()["latest"]
    duplicate = copy.deepcopy(latest); duplicate["payload"]["created_by"] = "other"
    duplicate["payload"]["release_id"] = t.release_id(duplicate["payload"])
    duplicate["signature"] = base64.b64encode(signing.sign(t.PREFIX + t.canonical_bytes(duplicate["payload"]), registry[2])).decode()
    (registry[1].directory / f"{duplicate['payload']['release_id']}.json").write_bytes(t.canonical_bytes(duplicate))
    assert not registry[1].verify_chain()["valid"]


def test_rotation_retirement_and_revocation_semantics(registry):
    key_a, _ = signing.generate_signing_keypair(); add_key(registry, key_a)
    store, root = registry[1], registry[2]
    generation = store.verify_chain()["count"] + 1
    keys = t.transition_keys(store.latest_keys(), signing.key_fingerprint(key_a.verify_key),
                             "RETIRED", generation, "scheduled rotation")
    key_b, _ = signing.generate_signing_keypair()
    keys.append(t.make_key_record(key_b.verify_key, "SNAPSHOT_SIGNER", "default", "snapshot-b", generation))
    store.create_release(root, "security", keys, kind="ROTATION", reason="scheduled rotation", when=WHEN)
    assert store.classify_key(signing.key_fingerprint(key_a.verify_key), "SNAPSHOT_SIGNER", "default")["classification"] == "SIGNED_BY_RETIRED_KEY"
    assert store.authorize(key_b, "SNAPSHOT_SIGNER", "default")["classification"] == "TRUSTED_ACTIVE"
    with pytest.raises(t.TrustRegistryError): store.authorize(key_a, "SNAPSHOT_SIGNER", "default")
    generation += 1
    keys = t.transition_keys(store.latest_keys(), signing.key_fingerprint(key_a.verify_key),
                             "REVOKED", generation, "suspected compromise")
    store.create_release(root, "security", keys, kind="REVOCATION", reason="suspected compromise", when=WHEN)
    assert store.classify_key(signing.key_fingerprint(key_a.verify_key), "SNAPSHOT_SIGNER", "default")["classification"] == "SIGNED_BY_REVOKED_KEY"
    with pytest.raises(t.TrustRegistryError):
        t.transition_keys(store.latest_keys(), signing.key_fingerprint(key_a.verify_key), "RETIRED", generation + 1, "undo")


def test_exact_release_binding_and_historical_key_classification(registry):
    key, _ = signing.generate_signing_keypair()
    issued = add_key(registry, key)
    store, root = registry[1], registry[2]
    binding = store.binding_for_release(issued)
    assert store.resolve_binding(binding) == issued
    at_issuance = store.classify_key_at(
        binding, signing.key_fingerprint(key.verify_key), "SNAPSHOT_SIGNER", "default")
    assert at_issuance["classification"] == "TRUSTED_ACTIVE"

    generation = store.verify_chain()["count"] + 1
    keys = t.transition_keys(store.latest_keys(), signing.key_fingerprint(key.verify_key),
                             "RETIRED", generation, "rotation pending")
    store.create_release(root, "security", keys, kind="UPDATE", when=WHEN)
    assert store.classify_key(signing.key_fingerprint(key.verify_key),
                              "SNAPSHOT_SIGNER", "default")["classification"] == "SIGNED_BY_RETIRED_KEY"
    assert store.classify_key_at(
        binding, signing.key_fingerprint(key.verify_key), "SNAPSHOT_SIGNER", "default"
    )["classification"] == "TRUSTED_ACTIVE"


@pytest.mark.parametrize("field,value", [
    ("registry_id", "other"), ("generation", 99),
    ("release_id", "TRR-" + "0" * 64), ("release_digest", "0" * 64),
    ("root_key_id", "SHA256:" + "0" * 64),
])
def test_exact_release_binding_rejects_mismatch(registry, field, value):
    binding = registry[1].binding_for_release(registry[4])
    binding[field] = value
    with pytest.raises(t.TrustRegistryError, match="registry release binding mismatch"):
        registry[1].resolve_binding(binding)


def test_snapshot_creation_rotation_and_historical_verification(registry, tmp_path):
    key_a, _ = signing.generate_signing_keypair(); add_key(registry, key_a)
    ws = IncidentWorkspace.declare(registry[0], title="Trust snapshot", severity="SEV2", actor="analyst")
    first = ws.create_snapshot(key_a, "analyst", when=WHEN)
    store, root = registry[1], registry[2]; generation = store.verify_chain()["count"] + 1
    keys = t.transition_keys(store.latest_keys(), signing.key_fingerprint(key_a.verify_key), "RETIRED", generation, "rotate")
    key_b, _ = signing.generate_signing_keypair()
    keys.append(t.make_key_record(key_b.verify_key, "SNAPSHOT_SIGNER", "default", "snapshot-b", generation))
    store.create_release(root, "security", keys, kind="ROTATION", reason="rotate", when=WHEN)
    assert ws.verify_snapshot(first["payload"]["snapshot_id"])["signer_status"] == "SIGNED_BY_RETIRED_KEY"
    with pytest.raises(s.SnapshotError): ws.create_snapshot(key_a, "analyst", when=WHEN)
    ws.add_observation("after rotation", "analyst")
    second = ws.create_snapshot(key_b, "analyst", when=WHEN)
    assert ws.verify_snapshot(second["payload"]["snapshot_id"])["signer_status"] == "TRUSTED_ACTIVE"


def test_registry_snapshot_creation_emits_trust_bound_v2(registry):
    key, _ = signing.generate_signing_keypair(); release = add_key(registry, key)
    ws = IncidentWorkspace.declare(registry[0], title="Bound snapshot", severity="SEV2", actor="analyst")

    document = ws.create_snapshot(key, "analyst", when=WHEN)
    payload = document["payload"]

    assert payload["domain"] == "coreline.incident-snapshot.v2"
    assert payload["schema_version"] == 2
    assert payload["registry_binding"] == registry[1].binding_for_release(release)
    result = ws.verify_snapshot(payload["snapshot_id"])
    assert result["valid"] and result["signature_valid"]
    assert result["issuance_authorized"]
    assert result["authorization_status"] == "ISSUANCE_AUTHORIZED"


def test_snapshot_v2_uses_issuance_release_but_current_revocation_wins(registry):
    key, _ = signing.generate_signing_keypair(); add_key(registry, key)
    ws = IncidentWorkspace.declare(registry[0], title="Historical authorization", severity="SEV2", actor="analyst")
    document = ws.create_snapshot(key, "analyst", when=WHEN)
    store, root = registry[1], registry[2]

    generation = store.verify_chain()["count"] + 1
    retired = t.transition_keys(store.latest_keys(), signing.key_fingerprint(key.verify_key),
                                "RETIRED", generation, "rotation pending")
    store.create_release(root, "security", retired, kind="UPDATE", when=WHEN)
    result = ws.verify_snapshot(document["payload"]["snapshot_id"])
    assert result["valid"] and result["issuance_authorized"]

    generation += 1
    revoked = t.transition_keys(store.latest_keys(), signing.key_fingerprint(key.verify_key),
                                "REVOKED", generation, "compromised")
    store.create_release(root, "security", revoked, kind="REVOCATION", reason="compromised", when=WHEN)
    result = ws.verify_snapshot(document["payload"]["snapshot_id"])
    assert result["signature_valid"] and result["issuance_authorized"] and not result["valid"]
    assert result["signer_status"] == "SIGNED_BY_REVOKED_KEY"


def test_snapshot_chain_allows_v1_to_v2_but_rejects_schema_downgrade(tmp_path, monkeypatch):
    monkeypatch.delenv("CORELINE_TRUST_EXPECTED_TIP", raising=False)
    home = tmp_path / "home"
    ws = IncidentWorkspace.declare(home, title="Migration", severity="SEV2", actor="analyst")
    key, public = signing.generate_signing_keypair()
    pin = home / "trust" / "snapshot.verify.json"
    s._publish(pin, s.canonical_bytes({"algorithm": "ed25519", "verify_key": signing.encode_verify_key(public),
                                      "fingerprint": signing.key_fingerprint(public)}), 0o644)
    legacy_store = s.SnapshotStore(ws)
    first = legacy_store.create(key, "analyst", WHEN)
    assert first["payload"]["schema_version"] == 1

    root, root_public = signing.generate_signing_keypair()
    t.write_root_pin(t.root_path(home), "org-migration", root_public)
    registry_store = t.TrustRegistryStore(t.releases_path(home), t.load_root_pin(t.root_path(home)))
    registry_store.create_release(root, "security", [
        t.make_key_record(public, "SNAPSHOT_SIGNER", "default", "snapshot", 1)
    ], kind="BOOTSTRAP", when=WHEN)
    current_store = s.SnapshotStore(ws)
    second = current_store.create(key, "analyst", WHEN)
    assert second["payload"]["schema_version"] == 2
    assert current_store.verify_chain()["valid"]

    with pytest.raises(s.SnapshotError, match="downgrade"):
        legacy_store.create(key, "analyst", WHEN)


def _resign_v2(document, key):
    document = copy.deepcopy(document)
    document["payload"]["snapshot_id"] = s.snapshot_id(document["payload"])
    document["signature"] = base64.b64encode(signing.sign(
        s.PREFIX_V2 + s.canonical_bytes(document["payload"]), key)).decode()
    return document


@pytest.mark.parametrize("damage,status", [
    ("missing", "REGISTRY_BINDING_MISSING"),
    ("mismatch", "REGISTRY_BINDING_MISMATCH"),
    ("unknown", "REGISTRY_RELEASE_UNKNOWN"),
])
def test_snapshot_v2_binding_failures_are_distinct(registry, damage, status):
    key, _ = signing.generate_signing_keypair(); add_key(registry, key)
    ws = IncidentWorkspace.declare(registry[0], title="Binding failures", severity="SEV2", actor="analyst")
    store = s.SnapshotStore(ws)
    document = ws.create_snapshot(key, "analyst", when=WHEN)
    binding = document["payload"]["registry_binding"]
    if damage == "missing":
        del document["payload"]["registry_binding"]
    elif damage == "mismatch":
        binding["release_digest"] = "0" * 64
    else:
        binding["generation"] = 999
        binding["release_id"] = "TRR-" + "0" * 64
        binding["release_digest"] = "0" * 64
    result = store._check_document(_resign_v2(document, key))
    assert not result["valid"] and result["authorization_status"] == status
    assert status in result["errors"]


def test_snapshot_v2_rejects_signer_not_active_in_bound_release(registry):
    key, _ = signing.generate_signing_keypair(); add_key(registry, key)
    ws = IncidentWorkspace.declare(registry[0], title="Issuance status", severity="SEV2", actor="analyst")
    store = s.SnapshotStore(ws)
    document = ws.create_snapshot(key, "analyst", when=WHEN)
    document["payload"]["registry_binding"] = registry[1].binding_for_release(registry[4])
    result = store._check_document(_resign_v2(document, key))
    assert result["signature_valid"] and not result["valid"]
    assert result["authorization_status"] == "SIGNER_NOT_ACTIVE_AT_ISSUANCE"


def test_snapshot_v2_chain_rejects_registry_generation_rollback(registry):
    key, _ = signing.generate_signing_keypair(); release_two = add_key(registry, key)
    anchor, _ = signing.generate_signing_keypair()
    add_key(registry, anchor, "ANCHOR_SIGNER", "vault-a", "anchor-a")
    ws = IncidentWorkspace.declare(registry[0], title="Binding rollback", severity="SEV2", actor="analyst")
    store = s.SnapshotStore(ws)
    first = ws.create_snapshot(key, "analyst", when=WHEN)
    assert first["payload"]["registry_binding"]["generation"] == 3
    second = ws.create_snapshot(key, "analyst", when=WHEN)
    old_path = store.directory / f"{second['payload']['snapshot_id']}.json"
    old_path.unlink()
    second["payload"]["registry_binding"] = registry[1].binding_for_release(release_two)
    second = _resign_v2(second, key)
    (store.directory / f"{second['payload']['snapshot_id']}.json").write_bytes(s.canonical_bytes(second))
    result = store.verify_chain()
    assert not result["valid"] and "REGISTRY_GENERATION_ROLLBACK" in result["errors"]


def test_revoked_snapshot_is_qualified_and_fails_trust(registry):
    key, _ = signing.generate_signing_keypair(); add_key(registry, key)
    ws = IncidentWorkspace.declare(registry[0], title="Revoked", severity="SEV2", actor="analyst")
    doc = ws.create_snapshot(key, "analyst", when=WHEN)
    store, root = registry[1], registry[2]; generation = store.verify_chain()["count"] + 1
    keys = t.transition_keys(store.latest_keys(), signing.key_fingerprint(key.verify_key), "REVOKED", generation, "compromised")
    store.create_release(root, "security", keys, kind="REVOCATION", reason="compromised", when=WHEN)
    result = ws.verify_snapshot(doc["payload"]["snapshot_id"])
    assert result["signature_valid"] and not result["valid"]
    assert result["signer_status"] == "SIGNED_BY_REVOKED_KEY"


def test_sealing_uses_active_registry_key_and_rejects_retired_key(registry, tmp_path):
    key_a, _ = signing.generate_signing_keypair(); add_key(registry, key_a)
    ws = IncidentWorkspace.declare(registry[0], title="Registry seal", severity="SEV2", actor="analyst")
    evidence = tmp_path / "evidence"; evidence.write_text("preserved")
    ws.add_evidence(str(evidence), "event", "analyst")
    subject = ws.create_subject("HOST", "host", "analyst")
    observation = ws.add_observation("observed", "analyst", subject_refs=[subject.subject_id])
    claim = ws.add_claim("claim", "analyst", [observation.observation_id])
    action = ws.create_action("contain", "done", "analyst", claim_refs=[claim.claim_id])
    ws.create_decision("review", "approved", "reason", "human", "analyst", action_refs=[action.action_id])
    ws.transition("RESOLVED", "analyst"); ws.close_incident("analyst")
    store, root = registry[1], registry[2]; generation = store.verify_chain()["count"] + 1
    keys = t.transition_keys(store.latest_keys(), signing.key_fingerprint(key_a.verify_key), "RETIRED", generation, "rotate")
    key_b, _ = signing.generate_signing_keypair()
    keys.append(t.make_key_record(key_b.verify_key, "SNAPSHOT_SIGNER", "default", "snapshot-b", generation))
    store.create_release(root, "security", keys, kind="ROTATION", reason="rotate", when=WHEN)
    with pytest.raises(Exception, match="external signing key"):
        ws.seal_incident("analyst", snapshot_signing_key=key_a)
    ws.seal_incident("analyst", snapshot_signing_key=key_b)
    assert ws.is_sealed and ws.verify()["ok"]


def test_anchor_rotation_preserves_old_receipt_and_rejects_retired_signing(registry, tmp_path):
    snapshot_key, _ = signing.generate_signing_keypair(); add_key(registry, snapshot_key)
    anchor_a, anchor_pub = signing.generate_signing_keypair()
    add_key(registry, anchor_a, "ANCHOR_SIGNER", "vault-a", "anchor-a")
    ws = IncidentWorkspace.declare(registry[0], title="Anchor rotation", severity="SEV2", actor="analyst")
    config_path = tmp_path / "anchors.json"; anchor_root = tmp_path / "anchor-ledger"
    a.write_registry(config_path, "vault-a", anchor_root, anchor_pub)
    config = a.load_registry(config_path, incident_dir=ws.dir)
    doc = ws.create_snapshot(snapshot_key, "analyst", when=WHEN)
    manager = a.AnchorManager(ws, config)
    first = manager.anchor_snapshot(doc["payload"]["snapshot_id"], anchor_a, WHEN)
    store, root = registry[1], registry[2]; generation = store.verify_chain()["count"] + 1
    keys = t.transition_keys(store.latest_keys(), signing.key_fingerprint(anchor_a.verify_key), "RETIRED", generation, "rotate")
    anchor_b, _ = signing.generate_signing_keypair()
    keys.append(t.make_key_record(anchor_b.verify_key, "ANCHOR_SIGNER", "vault-a", "anchor-b", generation))
    store.create_release(root, "security", keys, kind="ROTATION", reason="rotate", when=WHEN)
    assert manager.verify_anchor_receipt(first["payload"]["receipt_id"])["signer_status"] == "SIGNED_BY_RETIRED_KEY"
    with pytest.raises(a.AnchorError): manager.anchor_snapshot(doc["payload"]["snapshot_id"], anchor_a, WHEN)


def test_gcs_anchor_rotation_resolves_historical_and_active_keys(registry, tmp_path, monkeypatch):
    snapshot_key, _ = signing.generate_signing_keypair(); add_key(registry, snapshot_key)
    anchor_a, anchor_pub = signing.generate_signing_keypair()
    add_key(registry, anchor_a, "ANCHOR_SIGNER", "vault-gcs", "anchor-a")
    ws = IncidentWorkspace.declare(registry[0], title="GCS trust rotation", severity="SEV2", actor="analyst")
    config_path = tmp_path / "gcs-anchors.json"
    a.write_gcs_registry(config_path, "vault-gcs", "coreline-anchor", "org/coreline", anchor_pub)
    config = a.load_registry(config_path, incident_dir=ws.dir); fake = FakeGCS()
    monkeypatch.setattr(GCSAnchor, "keyless", classmethod(
        lambda cls, bucket, prefix, anchor_id, verify_key, signing_key=None, key_resolver=None:
        cls(bucket, prefix, anchor_id, verify_key, signing_key, client=fake, key_resolver=key_resolver)))
    manager = a.AnchorManager(ws, config)
    first_doc = ws.create_snapshot(snapshot_key, "analyst", when=WHEN)
    first = manager.anchor_snapshot(first_doc["payload"]["snapshot_id"], anchor_a, WHEN)
    store, root = registry[1], registry[2]; generation = store.verify_chain()["count"] + 1
    keys = t.transition_keys(store.latest_keys(), signing.key_fingerprint(anchor_a.verify_key), "RETIRED", generation, "rotate")
    anchor_b, _ = signing.generate_signing_keypair()
    keys.append(t.make_key_record(anchor_b.verify_key, "ANCHOR_SIGNER", "vault-gcs", "anchor-b", generation))
    store.create_release(root, "security", keys, kind="ROTATION", reason="rotate", when=WHEN)
    ws.add_observation("new state", "analyst")
    second_doc = ws.create_snapshot(snapshot_key, "analyst", when=WHEN)
    second = manager.anchor_snapshot(second_doc["payload"]["snapshot_id"], anchor_b, WHEN)
    assert manager.provider().verify_ledger(ws.incident_id)["valid"]
    assert manager.verify_anchor_receipt(first["payload"]["receipt_id"])["signer_status"] == "SIGNED_BY_RETIRED_KEY"
    assert manager.verify_anchor_receipt(second["payload"]["receipt_id"])["signer_status"] == "TRUSTED_ACTIVE"


def test_expected_tip_detects_authentic_registry_rollback(registry):
    key, _ = signing.generate_signing_keypair(); add_key(registry, key)
    latest = registry[1].verify_chain()["latest"]
    (registry[1].directory / f"{latest['payload']['release_id']}.json").unlink()
    tip = registry[1].expected_tip()
    assert not tip["valid"] and tip["relation"] == "LOCAL_BEHIND_EXPECTED"
    assert not registry[1].health()["valid"]


def test_expected_tip_unavailable_is_distinct_and_required_fails(registry, monkeypatch):
    with monkeypatch.context() as scoped:
        scoped.setattr(t, "_read", lambda *args: (_ for _ in ()).throw(PermissionError()))
        tip = registry[1].expected_tip()
    assert tip["relation"] == "UNAVAILABLE" and not tip["checked"] and tip["valid"] is None
    monkeypatch.setattr(registry[1], "expected_tip", lambda: tip)
    assert registry[1].health()["valid"]
    assert not registry[1].health(require_expected=True)["valid"]


def test_bundle_newer_import_and_rollback_conflict_rejected(registry, tmp_path):
    key, _ = signing.generate_signing_keypair(); add_key(registry, key)
    bundle = registry[1].export_bundle()
    assert signing.decode_verify_key(bundle["root_verify_key"]) == registry[3]
    target = t.TrustRegistryStore(tmp_path / "imported", registry[1].pin)
    target.import_bundle(bundle)
    assert target.verify_chain()["count"] == 2
    with pytest.raises(t.TrustRegistryError): target.import_bundle({**bundle, "releases": bundle["releases"][:1]})
    attacker = copy.deepcopy(bundle); attacker["registry_id"] = "other"
    with pytest.raises(t.TrustRegistryError): target.import_bundle(attacker)
    _, attacker_public = signing.generate_signing_keypair()
    attacker = copy.deepcopy(bundle); attacker["root_verify_key"] = signing.encode_verify_key(attacker_public)
    with pytest.raises(t.TrustRegistryError): target.import_bundle(attacker)


@pytest.mark.parametrize("bad", [None, {}, [], b"bad", {"payload": {}, "signature": "x"}])
def test_malformed_release_never_verifies(bad, registry):
    assert not t.verify_release(bad, registry[3])["valid"]


def test_duplicate_json_keys_and_symlink_release_fail(registry, tmp_path):
    bad = registry[1].directory / ("TRR-" + "0" * 64 + ".json")
    bad.write_text('{"payload":{},"payload":{},"signature":"x"}')
    assert not registry[1].verify_chain()["valid"]
    bad.unlink(); target = tmp_path / "target"; target.write_text("{}")
    bad.symlink_to(target)
    assert not registry[1].verify_chain()["valid"]


def test_malformed_utf8_and_unknown_key_fail_closed(registry):
    path = registry[1].directory / ("TRR-" + "0" * 64 + ".json")
    path.write_bytes(b"\xff\xfe")
    assert not registry[1].verify_chain()["valid"]
    path.unlink()
    result = registry[1].classify_key("SHA256:" + "0" * 64, "SNAPSHOT_SIGNER", "default")
    assert result["classification"] == "UNKNOWN_KEY" and not result["trusted"]


def test_concurrent_release_writers_cannot_both_succeed(registry):
    key, _ = signing.generate_signing_keypair(); store, root = registry[1], registry[2]
    def create():
        generation = store.verify_chain()["count"] + 1
        keys = store.latest_keys() + [t.make_key_record(key.verify_key, "SNAPSHOT_SIGNER", "default", "one", generation)]
        try: return store.create_release(root, "security", keys, when=WHEN)
        except t.TrustRegistryError: return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: create(), range(2)))
    assert all(item is not None for item in results)
    assert results[0]["payload"]["release_id"] == results[1]["payload"]["release_id"]
    assert registry[1].verify_chain()["count"] == 2


def test_private_signing_material_never_appears_in_release(registry):
    key, _ = signing.generate_signing_keypair(); add_key(registry, key, identity="snapshot authority")
    encoded = json.dumps(registry[1].export_bundle())
    assert base64.b64encode(signing.encode_signing_key(key)).decode() not in encoded
