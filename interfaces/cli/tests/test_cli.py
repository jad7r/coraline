"""Smoke tests for the Typer CLI surface via CliRunner (no real terminal needed)."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from interfaces.cli.coreline import app

runner = CliRunner()


def _run(args, home: Path):
    return runner.invoke(app, args, env={"CORELINE_HOME": str(home), "CORELINE_ACTOR": "tester"})


def test_help_lists_all_commands():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    for cmd in (
        "declare", "doctor", "evidence", "timeline", "status", "report",
        "use", "close", "verify", "registry", "lifecycle", "observe", "claim",
    ):
        assert cmd in res.output


def test_full_flow_declare_evidence_timeline_status_report(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "alert.log"
    ev.write_text("exfil evidence\n", encoding="utf-8")

    r = _run(["declare", "--title", "DB Exfiltration Alert", "--severity", "SEV1"], home)
    assert r.exit_code == 0, r.output
    assert "INCIDENT DECLARED" in r.output

    r = _run(["evidence", "add", "--file", str(ev), "--note", "SIEM alert"], home)
    assert r.exit_code == 0, r.output
    assert "EVIDENCE SEALED" in r.output

    r = _run(["timeline", "show"], home)
    assert r.exit_code == 0, r.output
    assert "audit chain verified" in r.output

    r = _run(["status"], home)
    assert r.exit_code == 0, r.output
    assert "QUALITY GATES" in r.output

    r = _run(["report"], home)
    assert r.exit_code == 0, r.output
    assert "POST-INCIDENT REPORT" in r.output


def test_doctor_use_and_close_operator_flow(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "alert.log"
    ev.write_text("exfil evidence\n", encoding="utf-8")

    first = _run(["declare", "--title", "First", "--severity", "SEV3"], home)
    assert first.exit_code == 0, first.output
    first_id = (home / "CURRENT").read_text(encoding="utf-8").strip()

    second = _run(["declare", "--title", "Second", "--severity", "SEV2"], home)
    assert second.exit_code == 0, second.output

    r = _run(["use", first_id], home)
    assert r.exit_code == 0, r.output
    assert f"active incident set to {first_id}" in r.output

    r = _run(["doctor"], home)
    assert r.exit_code == 0, r.output
    assert "CORELINE DOCTOR" in r.output
    assert "workspace ready" in r.output

    r = _run(["verify"], home)
    assert r.exit_code == 0, r.output
    assert "verification passed" in r.output

    r = _run(["evidence", "add", "--file", str(ev), "--note", "SIEM alert"], home)
    assert r.exit_code == 0, r.output

    r = _run(["verify", "--all"], home)
    assert r.exit_code == 0, r.output
    assert "verification passed for 2 incident" in r.output

    r = _run(["close"], home)
    assert r.exit_code == 0, r.output
    assert "INCIDENT CLOSED" in r.output

    r = _run(["evidence", "add", "--file", str(ev)], home)
    assert r.exit_code == 1
    assert "evidence intake is locked" in r.output

    r = _run(["close"], home)
    assert r.exit_code == 1
    assert "already closed" in r.output


def test_verify_fails_when_stored_evidence_is_modified(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "alert.log"
    ev.write_text("exfil evidence\n", encoding="utf-8")

    r = _run(["declare", "--title", "DB Exfiltration Alert", "--severity", "SEV1"], home)
    assert r.exit_code == 0, r.output
    r = _run(["evidence", "add", "--file", str(ev), "--note", "SIEM alert"], home)
    assert r.exit_code == 0, r.output

    r = _run(["verify"], home)
    assert r.exit_code == 0, r.output

    stored = next((home / (home / "CURRENT").read_text(encoding="utf-8").strip() / "store").rglob("alert.log"))
    stored.write_text("modified evidence\n", encoding="utf-8")

    r = _run(["verify"], home)
    assert r.exit_code == 1
    assert "verification failed" in r.output
    assert "bad hash" in r.output

    r = _run(["doctor"], home)
    assert r.exit_code == 1
    assert "stored evidence artifacts failed verification" in r.output


def test_close_requires_green_preclosure_gates_or_forced_reason(tmp_path: Path):
    home = tmp_path / "incidents"
    r = _run(["declare", "--title", "False positive alert", "--severity", "SEV4"], home)
    assert r.exit_code == 0, r.output

    r = _run(["close"], home)
    assert r.exit_code == 1
    assert "unmet pre-closure gates" in r.output

    r = _run(["close", "--force"], home)
    assert r.exit_code == 1
    assert "forced closure requires a reason" in r.output

    r = _run(["close", "--force", "--reason", "False positive; no evidence artifact"], home)
    assert r.exit_code == 0, r.output
    assert "INCIDENT CLOSED" in r.output

    r = _run(["timeline", "show"], home)
    assert r.exit_code == 0, r.output
    assert "closure-override" in r.output


def test_observe_add_list_show_and_reject_missing_evidence(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "cloudtrail.json"
    ev.write_text('{"eventName":"GetSecretValue"}\n', encoding="utf-8")

    r = _run(["declare", "--title", "Credential exposure", "--severity", "SEV2"], home)
    assert r.exit_code == 0, r.output
    r = _run(["evidence", "add", "--file", str(ev), "--note", "CloudTrail"], home)
    assert r.exit_code == 0, r.output

    iid = (home / "CURRENT").read_text(encoding="utf-8").strip()
    manifest = json.loads((home / iid / "manifest.json").read_text(encoding="utf-8"))
    sha = manifest["items"][0]["sha256"]

    r = _run([
        "observe", "add",
        "--text", "CloudTrail shows secret access after credential exposure",
        "--evidence", sha[:16],
        "--disposition", "OBSERVED",
        "--subject", "prod/app-secret",
    ], home)
    assert r.exit_code == 0, r.output
    assert "OBSERVATION" in r.output
    obs_id = next(part for part in r.output.split() if part.startswith("OBS-"))

    r = _run(["observe", "list"], home)
    assert r.exit_code == 0, r.output
    assert obs_id in r.output
    assert "CloudTrail" in r.output
    assert "exposure" in r.output

    r = _run(["observe", "show", obs_id], home)
    assert r.exit_code == 0, r.output
    assert "prod/app-secret" in r.output
    assert sha[:12] in r.output

    r = _run([
        "observe", "correct", obs_id,
        "--text", "CloudTrail shows GetSecretValue after credential exposure",
        "--reason", "Use exact API name",
    ], home)
    assert r.exit_code == 0, r.output
    assert "correction recorded" in r.output

    r = _run(["observe", "show", obs_id], home)
    assert r.exit_code == 0, r.output
    assert "AMENDMENTS" in r.output
    assert "CORRECTION" in r.output

    r = _run(["observe", "retract", obs_id, "--reason", "Duplicate observation"], home)
    assert r.exit_code == 0, r.output
    assert "retraction recorded" in r.output

    r = _run(["observe", "list"], home)
    assert r.exit_code == 0, r.output
    assert "RETRACTED" in r.output

    r = _run(["observe", "correct", obs_id, "--text", "too late"], home)
    assert r.exit_code == 1
    assert "retracted" in r.output

    r = _run(["observe", "add", "--text", "bad ref", "--evidence", "f" * 64], home)
    assert r.exit_code == 1
    assert "evidence not found" in r.output

    r = _run(["timeline", "show"], home)
    assert r.exit_code == 0, r.output
    assert "observation-created" in r.output
    assert "observation-corrected" in r.output
    assert "observation-retracted" in r.output


def test_claim_add_list_show_and_rejects_bad_observation(tmp_path: Path):
    home = tmp_path / "incidents"

    r = _run(["declare", "--title", "Credential exposure", "--severity", "SEV2"], home)
    assert r.exit_code == 0, r.output

    r = _run([
        "observe", "add",
        "--text", "CloudTrail shows GetSecretValue after credential exposure",
        "--subject", "prod/app-secret",
    ], home)
    assert r.exit_code == 0, r.output
    obs_id = next(part for part in r.output.split() if part.startswith("OBS-"))

    r = _run([
        "claim", "add",
        "--text", "Production secret was accessed by exposed credential",
        "--observation", obs_id,
        "--status", "SUPPORTED",
        "--subject", "prod/app-secret",
    ], home)
    assert r.exit_code == 0, r.output
    assert "CLAIM" in r.output
    claim_id = next(part for part in r.output.split() if part.startswith("CLM-"))

    r = _run(["claim", "list"], home)
    assert r.exit_code == 0, r.output
    assert claim_id in r.output
    assert obs_id[:12] in r.output
    assert "credential" in r.output

    r = _run(["claim", "show", claim_id], home)
    assert r.exit_code == 0, r.output
    assert "prod/app-secret" in r.output
    assert obs_id in r.output

    r = _run([
        "claim", "correct", claim_id,
        "--text", "Production secret was accessed after credential exposure",
        "--reason", "Use precise wording",
    ], home)
    assert r.exit_code == 0, r.output
    assert "claim correction recorded" in r.output

    r = _run([
        "claim", "status", claim_id,
        "--status", "REFUTED",
        "--reason", "Follow-up IAM review disproved access",
    ], home)
    assert r.exit_code == 0, r.output
    assert "claim status recorded" in r.output

    r = _run(["claim", "show", claim_id], home)
    assert r.exit_code == 0, r.output
    assert "CLAIM AMENDMENTS" in r.output
    assert "CORRECTION" in r.output
    assert "STATUS" in r.output

    r = _run(["claim", "withdraw", claim_id, "--reason", "Superseded by final analysis"], home)
    assert r.exit_code == 0, r.output
    assert "claim withdrawal recorded" in r.output

    r = _run(["claim", "correct", claim_id, "--text", "too late"], home)
    assert r.exit_code == 1
    assert "withdrawn" in r.output

    r = _run(["claim", "add", "--text", "bad", "--observation", "OBS-NOPE"], home)
    assert r.exit_code == 1
    assert "observation not found" in r.output

    r = _run(["timeline", "show"], home)
    assert r.exit_code == 0, r.output
    assert "claim-created" in r.output
    assert "claim-corrected" in r.output
    assert "claim-status-updated" in r.output
    assert "claim-withdrawn" in r.output


def test_lifecycle_contain_and_resolve_flow(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "alert.log"
    ev.write_text("exfil evidence\n", encoding="utf-8")

    r = _run(["declare", "--title", "DB Exfiltration Alert", "--severity", "SEV1"], home)
    assert r.exit_code == 0, r.output

    r = _run(["lifecycle", "resolve", "--note", "Too early"], home)
    assert r.exit_code == 1
    assert "cannot resolve incident" in r.output

    r = _run(["evidence", "add", "--file", str(ev), "--note", "SIEM alert"], home)
    assert r.exit_code == 0, r.output

    r = _run(["lifecycle", "contain", "--note", "Blocked egress"], home)
    assert r.exit_code == 0, r.output
    assert "LIFECYCLE UPDATED" in r.output

    r = _run(["lifecycle", "eradicate", "--note", "Rotated exposed credential"], home)
    assert r.exit_code == 0, r.output
    assert "ERADICATING" in r.output

    r = _run(["lifecycle", "recover", "--note", "Validated database access"], home)
    assert r.exit_code == 0, r.output
    assert "RECOVERING" in r.output

    r = _run(["lifecycle", "resolve", "--note", "Customer impact ended"], home)
    assert r.exit_code == 0, r.output
    assert "RESOLVED" in r.output

    r = _run(["evidence", "add", "--file", str(ev), "--note", "late"], home)
    assert r.exit_code == 1
    assert "evidence intake is locked" in r.output

    r = _run(["timeline", "show"], home)
    assert r.exit_code == 0, r.output
    assert "lifecycle-transition" in r.output


def test_lifecycle_seal_requires_closed_incident(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "alert.log"
    ev.write_text("exfil evidence\n", encoding="utf-8")

    r = _run(["declare", "--title", "DB Exfiltration Alert", "--severity", "SEV1"], home)
    assert r.exit_code == 0, r.output
    r = _run(["evidence", "add", "--file", str(ev)], home)
    assert r.exit_code == 0, r.output

    r = _run(["lifecycle", "seal"], home)
    assert r.exit_code == 1
    assert "must be closed" in r.output

    r = _run(["close"], home)
    assert r.exit_code == 0, r.output

    r = _run(["lifecycle", "seal"], home)
    assert r.exit_code == 0, r.output
    assert "INCIDENT SEALED" in r.output

    r = _run(["report"], home)
    assert r.exit_code == 1
    assert "report generation is locked" in r.output


def test_lifecycle_refuses_regression(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "alert.log"
    ev.write_text("exfil evidence\n", encoding="utf-8")

    r = _run(["declare", "--title", "DB Exfiltration Alert", "--severity", "SEV1"], home)
    assert r.exit_code == 0, r.output
    r = _run(["evidence", "add", "--file", str(ev)], home)
    assert r.exit_code == 0, r.output
    r = _run(["lifecycle", "contain"], home)
    assert r.exit_code == 0, r.output

    r = _run(["lifecycle", "contain"], home)
    assert r.exit_code == 1
    assert "cannot move lifecycle" in r.output


def test_registry_init_trust_active_and_verify(tmp_path: Path):
    home = tmp_path / "incidents"
    r = _run(["declare", "--title", "DB Exfiltration Alert", "--severity", "SEV1"], home)
    assert r.exit_code == 0, r.output

    r = _run(["registry", "init"], home)
    assert r.exit_code == 0, r.output
    assert "REGISTRY INITIALIZED" in r.output
    assert (home / "trust" / "registry.json").exists()
    assert (home / "trust" / "registry.json.seal.json").exists()
    assert (home / "trust" / "root.key").exists()
    assert (home / "trust" / "root.verify.json").exists()

    r = _run(["registry", "verify", "--min-sequence", "1"], home)
    assert r.exit_code == 0, r.output
    assert "registry root seal verified" in r.output

    r = _run(["registry", "trust-active"], home)
    assert r.exit_code == 0, r.output
    assert "SIGNER TRUSTED" in r.output

    r = _run(["registry", "verify", "--min-sequence", "2"], home)
    assert r.exit_code == 0, r.output
    assert "signers" in r.output


def test_registry_verify_fails_after_registry_tamper(tmp_path: Path):
    home = tmp_path / "incidents"
    r = _run(["registry", "init"], home)
    assert r.exit_code == 0, r.output

    registry = home / "trust" / "registry.json"
    data = registry.read_text(encoding="utf-8")
    registry.write_text(data.replace('"sequence":1', '"sequence":2'), encoding="utf-8")

    r = _run(["registry", "verify"], home)
    assert r.exit_code == 1
    assert "REGISTRY VERIFICATION FAILED" in r.output


def test_commands_fail_cleanly_with_no_active_incident(tmp_path: Path):
    home = tmp_path / "empty"
    r = _run(["status"], home)
    assert r.exit_code == 1
    assert "no active incident" in r.output


def test_bad_severity_exits_nonzero(tmp_path: Path):
    home = tmp_path / "incidents"
    r = _run(["declare", "--title", "x", "--severity", "SEV9"], home)
    assert r.exit_code == 1
    assert "invalid severity" in r.output
