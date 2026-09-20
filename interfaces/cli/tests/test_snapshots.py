"""CLI checkpoint exits against real signed incidents; no network or persistent keys."""
import base64
import json

import pytest
from typer.testing import CliRunner

from core.incident import IncidentWorkspace
from core.incident import snapshots as s
from interfaces.cli.coreline import app


@pytest.fixture
def cli_case(tmp_path, monkeypatch):
    monkeypatch.delenv("CORELINE_SNAPSHOT_VERIFY_KEY", raising=False)
    ws = IncidentWorkspace.declare(tmp_path / "home", title="Checkpoint CLI", severity="SEV2", actor="tester")
    private = tmp_path / "external.key"
    def run(*args):
        return CliRunner().invoke(app, list(args), env={"CORELINE_HOME": str(ws.home), "CORELINE_ACTOR": "tester"})
    result = run("snapshot", "keygen", "--private-key", str(private))
    assert result.exit_code == 0, result.output
    return ws, private, run


def create(case):
    ws, private, run = case
    result = run("snapshot", "create", ws.incident_id, "--signing-key", str(private))
    assert result.exit_code == 0, result.output
    return s.SnapshotStore(ws).verify_chain()["latest"]["payload"]["snapshot_id"]


def test_cli_successful_public_verification_and_report(cli_case):
    ws, private, run = cli_case
    identifier = create(cli_case)
    private.unlink()
    for args, text in [
        (("snapshot", "list"), identifier),
        (("snapshot", "show", ws.incident_id, identifier), '"payload"'),
        (("snapshot", "verify", ws.incident_id, identifier), "VALID"),
        (("snapshot", "verify-chain"), "VALID"),
        (("snapshot", "compare-current", ws.incident_id, identifier), "CURRENT STATE MATCHES"),
        (("snapshot", "report"), "Signature valid: True"),
        (("verify",), "verification passed"),
        (("doctor",), "workspace ready"),
    ]:
        result = run(*args)
        assert result.exit_code == 0, result.output
        assert text in result.output


@pytest.mark.parametrize("damage", ["signature", "malformed", "missing-middle"])
def test_cli_failures_have_nonzero_exits(cli_case, damage):
    ws, private, run = cli_case
    identifier = create(cli_case)
    path = ws.dir / "snapshots" / f"{identifier}.json"
    if damage == "signature":
        doc = json.loads(path.read_text())
        doc["signature"] = base64.b64encode(b"x" * 64).decode()
        path.write_text(json.dumps(doc))
    elif damage == "malformed":
        path.write_text("{")
    else:
        create(cli_case)
        path.unlink()
    for args in [
        ("snapshot", "verify", ws.incident_id, identifier),
        ("snapshot", "verify-chain"), ("snapshot", "list"),
        ("snapshot", "compare-current", ws.incident_id, identifier),
        ("snapshot", "report"), ("verify",), ("doctor",),
    ]:
        result = run(*args)
        assert result.exit_code == 1, result.output
        assert isinstance(result.exception, SystemExit)


def test_cli_current_difference_and_expected_tip(cli_case):
    ws, _, run = cli_case
    first = create(cli_case)
    ws.add_observation("new fact", "tester")
    result = run("snapshot", "compare-current", ws.incident_id, first)
    assert result.exit_code == 1 and "CURRENT STATE DIFFERS" in result.output
    assert run("snapshot", "verify", ws.incident_id, first).exit_code == 0
    assert run("verify").exit_code == 0
    second = create(cli_case)
    (ws.dir / "snapshots" / f"{second}.json").unlink()
    assert run("snapshot", "verify-chain").exit_code == 0
    result = run("snapshot", "verify-chain", "--expected-tip", second)
    assert result.exit_code == 1 and "CHAIN BROKEN" in result.output


def test_explicit_and_environment_public_pins(cli_case, tmp_path, monkeypatch):
    ws, _, run = cli_case
    identifier = create(cli_case)
    public = tmp_path / "independent-pin.json"
    (ws.home / "trust" / "snapshot.verify.json").rename(public)
    assert run("verify").exit_code == 1
    assert run("verify", "--snapshot-verify-key", str(public)).exit_code == 0
    assert run("snapshot", "verify", ws.incident_id, identifier, "--verify-key", str(public)).exit_code == 0
    monkeypatch.setenv("CORELINE_SNAPSHOT_VERIFY_KEY", str(public))
    assert run("verify").exit_code == 0
    assert run("doctor").exit_code == 0
    inside = ws.dir / "attacker-pin.json"
    inside.write_bytes(public.read_bytes())
    assert run("verify", "--snapshot-verify-key", str(inside)).exit_code == 1
    assert run("snapshot", "verify", ws.incident_id, identifier, "--verify-key", str(inside)).exit_code == 1


def test_cli_seal_and_final_attestation(cli_case, tmp_path):
    ws, private, run = cli_case
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("evidence")
    ws.add_evidence(str(artifact), "test", "tester")
    create(cli_case)
    ws.close_incident("tester")
    assert "Integrity checkpoint" in (ws.dir / "report.md").read_text()
    assert run("lifecycle", "seal").exit_code == 1
    result = run("lifecycle", "seal", "--snapshot-key", str(private))
    assert result.exit_code == 0, result.output
    result = run("snapshot", "report")
    assert result.exit_code == 0 and "Final sealed checkpoint: True" in result.output
    assert run("verify").exit_code == 0


def test_cli_canary_errors_no_keys_or_dependency_values(cli_case, monkeypatch):
    ws, private, run = cli_case
    canary = "CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91"
    private.write_text(canary)
    result = run("snapshot", "create", "--signing-key", str(private))
    assert result.exit_code == 1 and canary not in result.output
    def fail(*args, **kwargs):
        raise RuntimeError(canary)
    monkeypatch.setattr(s.SnapshotStore, "create", fail)
    s.generate_key_files(ws.home, private.parent / "second.key", private.parent / "second.pub")
    result = run("snapshot", "create", "--signing-key", str(private.parent / "second.key"))
    assert result.exit_code == 1 and canary not in result.output


def test_keygen_never_overwrites_or_stores_private_in_incident(cli_case):
    ws, private, run = cli_case
    before = private.read_bytes()
    assert run("snapshot", "keygen", "--private-key", str(private)).exit_code == 1
    assert private.read_bytes() == before
    assert run("snapshot", "keygen", "--private-key", str(ws.dir / "secret")).exit_code == 1
    assert not (ws.dir / "secret").exists()


def test_public_pin_symlink_loop_controlled_cli_exit(cli_case, tmp_path):
    ws, _, run = cli_case
    identifier = create(cli_case)
    pin = tmp_path / "CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91"
    pin.symlink_to(pin)
    for args in [("verify", "--snapshot-verify-key", str(pin)),
                 ("snapshot", "verify", ws.incident_id, identifier, "--verify-key", str(pin)),
                 ("lifecycle", "seal", "--snapshot-verify-key", str(pin))]:
        result = run(*args)
        assert result.exit_code == 1 and isinstance(result.exception, SystemExit)
        assert pin.name not in result.output
