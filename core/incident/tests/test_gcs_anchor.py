"""Hermetic security tests for the GCS snapshot-anchor adapter."""
import copy
import inspect
from datetime import datetime, timezone

import pytest

from core.evidence.integrity import signing
from core.incident import anchors as a
from core.incident import IncidentWorkspace
from core.incident.gcs_anchor import GCSAnchor, validate_gcs_location
from core.incident import snapshots as s

WHEN = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


class FakePreconditionFailed(Exception):
    pass


class FakeGCS:
    def __init__(self):
        self.objects = {}
        self.fail_list = False
        self.fail_upload = False

    def bucket(self, name):
        return FakeBucket(self, name)

    def list_blobs(self, bucket, prefix):
        if self.fail_list:
            raise RuntimeError("CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91")
        return [FakeBlob(self, bucket, name) for (stored_bucket, name), _ in self.objects.items()
                if stored_bucket == bucket and name.startswith(prefix)]


class FakeBucket:
    def __init__(self, client, name):
        self.client, self.name = client, name

    def blob(self, name):
        return FakeBlob(self.client, self.name, name)


class FakeBlob:
    def __init__(self, client, bucket, name):
        self.client, self.bucket, self.name = client, bucket, name

    def upload_from_string(self, data, content_type=None, if_generation_match=None):
        if self.client.fail_upload:
            raise RuntimeError("CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91")
        key = (self.bucket, self.name)
        if if_generation_match != 0:
            raise AssertionError("anchor writes must be conditional creates")
        if key in self.client.objects:
            raise FakePreconditionFailed()
        self.client.objects[key] = bytes(data)

    def download_as_bytes(self):
        return self.client.objects[(self.bucket, self.name)]


def request(sequence=1, previous=None):
    return {
        "schema_version": 1, "incident_id": "INC-GCS", "snapshot_id": "SNP-" + f"{sequence:064x}",
        "snapshot_digest": f"{sequence + 10:064x}", "state_digest": f"{sequence + 20:064x}",
        "snapshot_signer_key_id": "snapshot-signer", "snapshot_sequence": sequence,
        "previous_snapshot_id": previous["payload"]["snapshot_id"] if previous else None,
        "previous_snapshot_digest": previous["payload"]["snapshot_digest"] if previous else None,
    }


@pytest.fixture
def provider():
    private, public = signing.generate_signing_keypair()
    fake = FakeGCS()
    return GCSAnchor("coreline-anchor", "coreline/anchors", "vault-gcs", public,
                     private, client=fake), fake, private, public


def test_capabilities_are_explicit_and_do_not_claim_retention_or_time(provider):
    assert provider[0].capabilities() == {
        "provider": "gcs-v1", "conditional_create": True, "durable_read": True,
        "durable_list": True, "retention_managed_externally": True,
        "retention_verified": False, "independently_trusted_time": False,
    }


def test_keyless_factory_accepts_no_credentials_or_key_file():
    params = set(inspect.signature(GCSAnchor.keyless).parameters)
    for forbidden in ("credentials", "key_file", "service_account", "token"):
        assert forbidden not in params


def test_append_verify_expected_tip_and_fixed_sequence_objects(provider):
    anchor, fake, _, public = provider
    r1 = anchor.anchor(request(), WHEN)
    r2 = anchor.anchor(request(2, r1), WHEN)
    ledger = anchor.verify_ledger("INC-GCS")
    assert ledger["valid"] and ledger["count"] == 2 and ledger["latest"] == r2
    assert anchor.get_expected_tip("INC-GCS") == r2
    assert a.verify_receipt(r2, public, anchor_id="vault-gcs", incident_id="INC-GCS",
                            anchor_type="gcs-v1")["valid"]
    names = sorted(name for bucket, name in fake.objects if bucket == "coreline-anchor")
    assert names[0].endswith("/00000000000000000001.json")
    assert names[1].endswith("/00000000000000000002.json")


def test_duplicate_is_idempotent_and_conflict_cannot_replace_sequence(provider):
    anchor, fake, *_ = provider
    r1 = anchor.anchor(request(), WHEN)
    assert anchor.anchor(request(), WHEN) == r1
    assert len(fake.objects) == 1
    conflicting = request()
    conflicting["state_digest"] = "f" * 64
    with pytest.raises(a.AnchorError):
        anchor.anchor(conflicting, WHEN)
    assert len(fake.objects) == 1


def test_two_writers_same_sequence_converge_on_first_receipt(provider, monkeypatch):
    first, fake, private, public = provider
    second = GCSAnchor("coreline-anchor", "coreline/anchors", "vault-gcs", public,
                       private, client=fake)
    original_upload = FakeBlob.upload_from_string
    raced = False

    def upload(self, data, **kwargs):
        nonlocal raced
        if not raced:
            raced = True
            second.anchor(request(), WHEN)
        return original_upload(self, data, **kwargs)

    monkeypatch.setattr(FakeBlob, "upload_from_string", upload)
    result = first.anchor(request(), WHEN)
    assert result == second.get_expected_tip("INC-GCS")
    assert len(fake.objects) == 1


def test_tampering_and_unexpected_object_break_ledger(provider):
    anchor, fake, *_ = provider
    receipt = anchor.anchor(request(), WHEN)
    key = next(iter(fake.objects))
    damaged = copy.deepcopy(receipt)
    damaged["payload"]["state_digest"] = "f" * 64
    fake.objects[key] = a.canonical_bytes(damaged)
    damaged_result = anchor.verify_ledger("INC-GCS")
    assert not damaged_result["valid"] and not damaged_result["unavailable"]
    fake.objects[key] = a.canonical_bytes(receipt)
    fake.objects[("coreline-anchor", anchor._ledger_prefix("INC-GCS") + "evil.json")] = b"{}"
    assert not anchor.verify_ledger("INC-GCS")["valid"]


def test_wrong_key_and_provider_type_substitution_fail(provider):
    anchor, _, _, _ = provider
    receipt = anchor.anchor(request(), WHEN)
    _, attacker = signing.generate_signing_keypair()
    assert not a.verify_receipt(receipt, attacker, anchor_type="gcs-v1")["valid"]
    assert not a.verify_receipt(receipt, anchor.verify_key, anchor_type="filesystem-v1")["valid"]


def test_unavailable_errors_are_redacted(provider):
    anchor, fake, *_ = provider
    fake.fail_list = True
    result = anchor.verify_ledger("INC-GCS")
    assert result["unavailable"] and "CORELINE_TEST_SECRET" not in str(result)
    fake.fail_list = False
    fake.fail_upload = True
    with pytest.raises(a.AnchorError) as caught:
        anchor.anchor(request(), WHEN)
    assert "CORELINE_TEST_SECRET" not in str(caught.value)


@pytest.mark.parametrize("bucket,prefix", [
    ("ok-bucket", "../escape"), ("ok-bucket", "/absolute"),
    ("ok-bucket", "a//b"), ("x", "valid"), ("UPPER", "valid"),
])
def test_location_validation_rejects_path_and_bucket_confusion(bucket, prefix):
    with pytest.raises(a.AnchorError):
        validate_gcs_location(bucket, prefix)


def test_registry_round_trip_and_provider_type_pin(tmp_path, provider):
    _, _, _, public = provider
    path = tmp_path / "anchors.json"
    a.write_gcs_registry(path, "vault-gcs", "coreline-anchor", "coreline/anchors",
                         public, "REQUIRED")
    loaded = a.load_registry(path)
    entry = loaded["anchors"]["vault-gcs"]
    assert entry["anchor_type"] == "gcs-v1" and entry["policy"] == "REQUIRED"
    assert "root" not in entry


def test_missing_sequence_and_snapshot_rollback_rejected(provider):
    anchor, *_ = provider
    with pytest.raises(a.AnchorError):
        anchor.anchor(request(2), WHEN)
    first = anchor.anchor(request(), WHEN)
    second = anchor.anchor(request(2, first), WHEN)
    with pytest.raises(a.AnchorError):
        anchor.anchor(request(), WHEN)
    assert anchor.get_expected_tip("INC-GCS") == second


def test_workspace_manager_uses_gcs_provider_and_detects_external_tip(tmp_path, monkeypatch, provider):
    _, fake, anchor_private, anchor_public = provider
    ws = IncidentWorkspace.declare(tmp_path / "home", title="GCS manager", severity="SEV2", actor="analyst")
    snapshot_path = tmp_path / "snapshot.key"
    s.generate_key_files(ws.home, snapshot_path, ws.home / "trust" / "snapshot.verify.json")
    snapshot_private = s.load_private_key(snapshot_path, ws.home)
    registry = tmp_path / "anchors.json"
    a.write_gcs_registry(registry, "vault-gcs", "coreline-anchor", "coreline/anchors",
                         anchor_public, "OPTIONAL")
    config = a.load_registry(registry, incident_dir=ws.dir)

    def keyless(cls, bucket, prefix, anchor_id, verify_key, signing_key=None):
        return cls(bucket, prefix, anchor_id, verify_key, signing_key, client=fake)

    monkeypatch.setattr(GCSAnchor, "keyless", classmethod(keyless))
    manager = a.AnchorManager(ws, config, snapshot_private.verify_key)
    document = ws.create_snapshot(snapshot_private, "analyst", when=WHEN)
    receipt = manager.anchor_snapshot(document["payload"]["snapshot_id"], anchor_private, WHEN)
    health = manager.health()
    assert health["valid"] and health["expected_tip_relation"] == "MATCH"
    assert health["anchor_capabilities"]["provider"] == "gcs-v1"
    assert health["receipt_id"] == receipt["payload"]["receipt_id"]


def test_gcs_expected_tip_exposes_local_snapshot_tail_deletion(tmp_path, monkeypatch, provider):
    _, fake, anchor_private, anchor_public = provider
    ws = IncidentWorkspace.declare(tmp_path / "home", title="GCS rollback", severity="SEV2", actor="analyst")
    snapshot_path = tmp_path / "snapshot.key"
    s.generate_key_files(ws.home, snapshot_path, ws.home / "trust" / "snapshot.verify.json")
    snapshot_private = s.load_private_key(snapshot_path, ws.home)
    registry = tmp_path / "anchors.json"
    a.write_gcs_registry(registry, "vault-gcs", "coreline-anchor", "coreline/anchors",
                         anchor_public, "OPTIONAL")
    config = a.load_registry(registry, incident_dir=ws.dir)
    monkeypatch.setattr(GCSAnchor, "keyless", classmethod(
        lambda cls, bucket, prefix, anchor_id, verify_key, signing_key=None:
        cls(bucket, prefix, anchor_id, verify_key, signing_key, client=fake)))
    manager = a.AnchorManager(ws, config, snapshot_private.verify_key)
    first = ws.create_snapshot(snapshot_private, "analyst", when=WHEN)
    manager.anchor_snapshot(first["payload"]["snapshot_id"], anchor_private, WHEN)
    ws.add_observation("later authenticated state", "analyst")
    second = ws.create_snapshot(snapshot_private, "analyst", when=WHEN)
    manager.anchor_snapshot(second["payload"]["snapshot_id"], anchor_private, WHEN)
    (ws.dir / "snapshots" / f"{second['payload']['snapshot_id']}.json").unlink()
    result = manager.health()
    assert not result["valid"] and result["expected_tip_relation"] == "LOCAL_BEHIND_EXPECTED"
