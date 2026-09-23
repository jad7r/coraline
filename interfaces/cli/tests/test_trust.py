"""CLI delegation and exit semantics for signed trust registries."""
import json

import pytest
from typer.testing import CliRunner

from core.evidence.integrity import signing
from core.incident import IncidentWorkspace
from core.incident import snapshots as s
from core.incident import trust_registry as t
from interfaces.cli.coreline import app


@pytest.fixture
def trust_cli(tmp_path, monkeypatch):
    home = tmp_path / "home"
    IncidentWorkspace.declare(home, title="Trust CLI", severity="SEV2", actor="tester")
    expected = tmp_path / "expected"
    monkeypatch.setenv("CORELINE_TRUST_EXPECTED_TIP", str(expected))
    root_key = tmp_path / "root.key"
    def run(*args):
        return CliRunner().invoke(app, list(args), env={"CORELINE_HOME": str(home),
                                                        "CORELINE_ACTOR": "tester",
                                                        "CORELINE_TRUST_EXPECTED_TIP": str(expected)})
    result = run("trust", "init", "--registry-id", "org-test", "--private-key", str(root_key),
                 "--actor", "security", "--expected-tip", str(expected))
    assert result.exit_code == 0, result.output
    return home, root_key, expected, run, tmp_path


def public_file(case, name):
    private, public = signing.generate_signing_keypair()
    path = case[4] / f"{name}.verify.json"
    path.write_text(json.dumps({"algorithm": "ed25519", "fingerprint": signing.key_fingerprint(public),
                                "verify_key": signing.encode_verify_key(public)}))
    return private, path


def test_status_release_key_and_rotation_workflow(trust_cli):
    _, root, _, run, _ = trust_cli
    key_a, public_a = public_file(trust_cli, "a")
    add = run("trust", "key", "add", "--public-key", str(public_a), "--purpose", "SNAPSHOT_SIGNER",
              "--scope", "default", "--identity", "snapshot-a", "--root-key", str(root), "--actor", "security")
    assert add.exit_code == 0, add.output
    key_id = signing.key_fingerprint(key_a.verify_key)
    _, public_b = public_file(trust_cli, "b")
    rotate = run("trust", "key", "rotate", "--old-key-id", key_id, "--public-key", str(public_b),
                 "--identity", "snapshot-b", "--reason", "scheduled", "--root-key", str(root),
                 "--actor", "security")
    assert rotate.exit_code == 0, rotate.output
    assert run("trust", "status", "--require-expected-tip").exit_code == 0
    listed = run("trust", "key", "list")
    assert listed.exit_code == 0 and "RETIRED" in listed.output and "ACTIVE" in listed.output
    assert run("trust", "release", "verify", "--require-expected-tip").exit_code == 0


def test_export_contains_public_material_and_invalid_import_fails(trust_cli):
    _, _, _, run, tmp_path = trust_cli
    output = tmp_path / "bundle.json"
    result = run("trust", "export", "--output", str(output))
    assert result.exit_code == 0 and output.exists()
    data = json.loads(output.read_text())
    assert data["bundle_schema_version"] == 1 and "private_key" not in output.read_text()
    bad = tmp_path / "bad.json"; bad.write_text('{"bundle_schema_version":1}')
    assert run("trust", "import", "--bundle", str(bad)).exit_code == 1


def test_recovery_requires_explicit_broken_continuity_acknowledgement(tmp_path):
    home = tmp_path / "recovery"; home.mkdir()
    args = ["trust", "init", "--registry-id", "recovered", "--private-key", str(tmp_path / "root.key"),
            "--actor", "security", "--trust-reset-from", "TRR-" + "0" * 64]
    env = {"CORELINE_HOME": str(home), "CORELINE_ACTOR": "tester"}
    assert CliRunner().invoke(app, args, env=env).exit_code == 1
    result = CliRunner().invoke(app, args + ["--acknowledge-broken-continuity"], env=env)
    assert result.exit_code == 0
    store = t.TrustRegistryStore.discover(home)
    latest = store.verify_chain()["latest"]["payload"]
    assert latest["transition"]["kind"] == "TRUST_RESET"


def test_verify_and_doctor_fail_on_registry_tampering(trust_cli):
    home, _, _, run, _ = trust_cli
    store = t.TrustRegistryStore.discover(home)
    latest = store.verify_chain()["latest"]
    path = store.directory / f"{latest['payload']['release_id']}.json"
    data = json.loads(path.read_text()); data["signature"] = "invalid"
    path.write_text(json.dumps(data))
    assert run("trust", "status").exit_code == 1
    assert run("verify").exit_code == 1
    assert run("doctor").exit_code == 1
