"""CLI anchor commands delegate to core and preserve verification exit semantics."""
import json

import pytest
from typer.testing import CliRunner

from core.incident import IncidentWorkspace
from core.incident.anchors import AnchorManager, load_registry, registry_path
from core.incident.snapshots import SnapshotStore
from interfaces.cli.coreline import app


@pytest.fixture
def anchor_cli(tmp_path):
    ws = IncidentWorkspace.declare(tmp_path / "home", title="Anchor CLI", severity="SEV2", actor="tester")
    snapshot_key = tmp_path / "snapshot.key"
    anchor_key = tmp_path / "anchor.key"
    anchor_root = tmp_path / "anchor-root"
    def run(*args):
        return CliRunner().invoke(app, list(args), env={"CORELINE_HOME": str(ws.home), "CORELINE_ACTOR": "tester"})
    assert run("snapshot", "keygen", "--private-key", str(snapshot_key)).exit_code == 0
    result = run("anchor", "init", "--anchor-id", "vault-a", "--root", str(anchor_root),
                 "--private-key", str(anchor_key))
    assert result.exit_code == 0, result.output
    return ws, snapshot_key, anchor_key, anchor_root, run


def create(case):
    ws, snapshot_key, _, _, run = case
    result = run("snapshot", "create", ws.incident_id, "--signing-key", str(snapshot_key))
    assert result.exit_code == 0, result.output
    return SnapshotStore(ws).verify_chain()["latest"]["payload"]["snapshot_id"]


def anchor(case, snapshot_id):
    ws, _, anchor_key, _, run = case
    result = run("anchor", "snapshot", ws.incident_id, snapshot_id, "--signing-key", str(anchor_key))
    assert result.exit_code == 0, result.output
    return AnchorManager(ws).provider().get_expected_tip(ws.incident_id)["payload"]["receipt_id"]


def test_anchor_cli_workflow_and_offline_verification(anchor_cli):
    ws, _, _, _, run = anchor_cli
    snapshot_id = create(anchor_cli)
    receipt_id = anchor(anchor_cli, snapshot_id)
    checks = [
        (("anchor", "list"), receipt_id),
        (("anchor", "show", ws.incident_id, receipt_id), '"payload"'),
        (("anchor", "verify", ws.incident_id, receipt_id), "OFFLINE RECEIPT VERIFIED"),
        (("anchor", "expected-tip"), "Expected relation: MATCH"),
        (("anchor", "verify-tip"), "EXPECTED TIP MATCHES"),
        (("anchor", "status"), '"expected_tip_relation": "MATCH"'),
        (("anchor", "status", "--offline"), "OFFLINE_RECEIPT_VERIFIED"),
        (("verify",), "verification passed"),
        (("doctor",), "workspace ready"),
    ]
    for args, expected in checks:
        result = run(*args)
        assert result.exit_code == 0, result.output
        assert expected in result.output


def test_cli_local_ahead_is_valid_optional(anchor_cli):
    ws, *_rest, run = anchor_cli
    first = create(anchor_cli); anchor(anchor_cli, first)
    ws.add_observation("new", "tester"); create(anchor_cli)
    result = run("anchor", "verify-tip")
    assert result.exit_code == 0 and "LOCAL AHEAD OF EXPECTED TIP" in result.output
    assert run("verify").exit_code == 0


def test_cli_local_behind_fails_after_external_anchor(anchor_cli):
    ws, *_ = anchor_cli
    first = create(anchor_cli); anchor(anchor_cli, first)
    ws.add_observation("new", "tester"); second = create(anchor_cli); anchor(anchor_cli, second)
    (ws.dir / "snapshots" / f"{second}.json").unlink()
    for path in (ws.dir / "anchors" / "vault-a").glob("*.json"):
        path.unlink()
    result = anchor_cli[4]("anchor", "verify-tip")
    assert result.exit_code == 1 and "LOCAL BEHIND EXPECTED TIP" in result.output
    assert anchor_cli[4]("verify").exit_code == 1
    assert anchor_cli[4]("doctor").exit_code == 1


def test_cli_tampered_receipt_nonzero_and_no_canary(anchor_cli):
    ws, *_ = anchor_cli
    snapshot_id = create(anchor_cli); receipt_id = anchor(anchor_cli, snapshot_id)
    path = ws.dir / "anchors" / "vault-a" / f"{receipt_id}.json"
    data = json.loads(path.read_text())
    data["signature"] = "CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91"
    path.write_text(json.dumps(data))
    for args in [("anchor", "verify", ws.incident_id, receipt_id), ("anchor", "status"),
                 ("snapshot", "report"), ("verify",), ("doctor",)]:
        result = anchor_cli[4](*args)
        assert result.exit_code == 1
        assert "CORELINE_TEST_SECRET" not in result.output


def test_required_policy_online_and_offline(anchor_cli):
    ws, *_ = anchor_cli
    path = registry_path(ws.home)
    data = json.loads(path.read_text()); data["anchors"][0]["policy"] = "REQUIRED"
    path.write_text(json.dumps(data))
    assert anchor_cli[4]("verify").exit_code == 1
    snapshot_id = create(anchor_cli); anchor(anchor_cli, snapshot_id)
    assert anchor_cli[4]("verify").exit_code == 0
    assert anchor_cli[4]("verify", "--anchor-offline").exit_code == 1


def test_required_for_seal_cli(anchor_cli, tmp_path):
    ws, snapshot_key, anchor_key, _, run = anchor_cli
    path = registry_path(ws.home)
    data = json.loads(path.read_text()); data["anchors"][0]["policy"] = "REQUIRED_FOR_SEAL"
    path.write_text(json.dumps(data))
    evidence = tmp_path / "evidence"; evidence.write_text("preserved")
    ws.add_evidence(str(evidence), "test", "tester")
    first = create(anchor_cli); anchor(anchor_cli, first)
    ws.close_incident("tester")
    result = run("lifecycle", "seal", "--snapshot-key", str(snapshot_key), "--anchor-key", str(anchor_key))
    assert result.exit_code == 0, result.output
    assert run("anchor", "verify-tip").exit_code == 0
    assert run("verify").exit_code == 0


@pytest.mark.parametrize("command", [
    ("anchor", "show", "INC-NOT-FOUND", "ANC-" + "0" * 64),
    ("anchor", "verify", "INC-NOT-FOUND", "ANC-" + "0" * 64),
    ("anchor", "snapshot", "INC-NOT-FOUND", "SNP-" + "0" * 64, "--signing-key", "/missing"),
])
def test_malformed_missing_commands_controlled(anchor_cli, command):
    result = anchor_cli[4](*command)
    assert result.exit_code == 1 and isinstance(result.exception, SystemExit)


def test_init_refuses_storage_and_private_key_under_home(anchor_cli):
    ws, _, _, _, run = anchor_cli
    result = run("anchor", "init", "--anchor-id", "bad", "--root", str(ws.home / "anchor"),
                 "--private-key", str(ws.home / "secret"), "--registry", str(ws.home / "other.json"))
    assert result.exit_code == 1
    assert not (ws.home / "secret").exists()
