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
        "action", "subject", "decision", "graph",
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


def test_subject_create_list_show_and_use_in_records(tmp_path: Path):
    home = tmp_path / "incidents"

    r = _run(["declare", "--title", "Endpoint compromise", "--severity", "SEV2"], home)
    assert r.exit_code == 0, r.output

    r = _run([
        "subject", "create",
        "--type", "HOST",
        "--value", "host-01",
        "--display-name", "Compromised host",
        "--description", "EDR alert source",
    ], home)
    assert r.exit_code == 0, r.output
    assert "SUBJECT" in r.output
    subject_id = next(part for part in r.output.split() if part.startswith("SUB-"))

    r = _run(["subject", "list"], home)
    assert r.exit_code == 0, r.output
    assert subject_id in r.output
    assert "host-01" in r.output

    r = _run(["subject", "show", subject_id], home)
    assert r.exit_code == 0, r.output
    assert "Compromised host" in r.output

    r = _run([
        "observe", "add",
        "--text", "EDR shows unusual process execution",
        "--subject-id", subject_id,
    ], home)
    assert r.exit_code == 0, r.output
    obs_id = next(part for part in r.output.split() if part.startswith("OBS-"))

    r = _run([
        "claim", "add",
        "--text", "Host executed malware",
        "--observation", obs_id,
        "--subject-id", subject_id,
    ], home)
    assert r.exit_code == 0, r.output
    claim_id = next(part for part in r.output.split() if part.startswith("CLM-"))

    r = _run([
        "action", "create",
        "--type", "host-isolation",
        "--description", "Isolated host-01",
        "--claim", claim_id,
        "--subject-id", subject_id,
    ], home)
    assert r.exit_code == 0, r.output

    r = _run(["verify"], home)
    assert r.exit_code == 0, r.output

    r = _run(["subject", "create", "--type", "HOST", "--value", "host-01"], home)
    assert r.exit_code == 1
    assert "subject already exists" in r.output


def test_action_create_list_show_and_amendment_flow(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "edr.log"
    ev.write_text("host isolation telemetry\n", encoding="utf-8")

    r = _run(["declare", "--title", "Host compromise", "--severity", "SEV1"], home)
    assert r.exit_code == 0, r.output
    r = _run(["evidence", "add", "--file", str(ev), "--note", "EDR telemetry"], home)
    assert r.exit_code == 0, r.output

    iid = (home / "CURRENT").read_text(encoding="utf-8").strip()
    manifest = json.loads((home / iid / "manifest.json").read_text(encoding="utf-8"))
    sha = manifest["items"][0]["sha256"]

    r = _run(["observe", "add", "--text", "EDR shows malware execution", "--evidence", sha[:16]], home)
    assert r.exit_code == 0, r.output
    obs_id = next(part for part in r.output.split() if part.startswith("OBS-"))

    r = _run(["claim", "add", "--text", "Host was compromised", "--observation", obs_id], home)
    assert r.exit_code == 0, r.output
    claim_id = next(part for part in r.output.split() if part.startswith("CLM-"))

    r = _run([
        "action", "create",
        "--type", "host-isolation",
        "--description", "Isolated compromised host",
        "--status", "INITIATED",
        "--subject", "host-01",
        "--claim", claim_id,
        "--observation", obs_id,
        "--evidence", sha[:16],
        "--outcome", "Isolation command sent",
    ], home)
    assert r.exit_code == 0, r.output
    assert "ACTION" in r.output
    action_id = next(part for part in r.output.split() if part.startswith("ACT-"))

    r = _run(["action", "list"], home)
    assert r.exit_code == 0, r.output
    assert action_id[:12] in r.output
    assert "host-isolation" in r.output

    r = _run(["action", "show", action_id], home)
    assert r.exit_code == 0, r.output
    assert claim_id in r.output
    assert obs_id in r.output
    assert sha[:12] in r.output

    r = _run([
        "action", "amend", action_id,
        "--description", "Isolated host-01 from production network",
        "--reason", "Add hostname",
    ], home)
    assert r.exit_code == 0, r.output
    assert "action correction recorded" in r.output

    r = _run([
        "action", "status", action_id,
        "--status", "COMPLETED",
        "--reason", "EDR confirmed isolation",
    ], home)
    assert r.exit_code == 0, r.output
    assert "action status recorded" in r.output

    r = _run([
        "action", "outcome", action_id,
        "--outcome", "Host isolation confirmed",
        "--reason", "EDR state verified",
    ], home)
    assert r.exit_code == 0, r.output
    assert "action outcome recorded" in r.output

    r = _run(["action", "show", action_id], home)
    assert r.exit_code == 0, r.output
    assert "ACTION AMENDMENTS" in r.output
    assert "CORRECTION" in r.output
    assert "STATUS" in r.output
    assert "OUTCOME" in r.output

    r = _run(["action", "cancel", action_id, "--reason", "Superseded by containment playbook"], home)
    assert r.exit_code == 0, r.output
    assert "action cancellation recorded" in r.output

    r = _run(["action", "amend", action_id, "--description", "too late"], home)
    assert r.exit_code == 1
    assert "cancelled" in r.output

    r = _run(["action", "create", "--type", "bad", "--description", "bad", "--claim", "CLM-NOPE"], home)
    assert r.exit_code == 1
    assert "claim not found" in r.output

    r = _run(["timeline", "show"], home)
    assert r.exit_code == 0, r.output
    assert "action-created" in r.output
    assert "action-corrected" in r.output
    assert "action-status-updated" in r.output
    assert "action-outcome-updated" in r.output
    assert "action-cancelled" in r.output


def test_decision_create_list_show_and_amendment_flow(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "edr.log"
    ev.write_text("host isolation telemetry\n", encoding="utf-8")

    r = _run(["declare", "--title", "Host compromise", "--severity", "SEV1"], home)
    assert r.exit_code == 0, r.output
    r = _run(["evidence", "add", "--file", str(ev), "--note", "EDR telemetry"], home)
    assert r.exit_code == 0, r.output
    iid = (home / "CURRENT").read_text(encoding="utf-8").strip()
    manifest = json.loads((home / iid / "manifest.json").read_text(encoding="utf-8"))
    sha = manifest["items"][0]["sha256"]

    r = _run(["subject", "create", "--type", "HOST", "--value", "host-01"], home)
    assert r.exit_code == 0, r.output
    subject_id = next(part for part in r.output.split() if part.startswith("SUB-"))
    r = _run(["observe", "add", "--text", "EDR shows malware execution",
              "--evidence", sha[:16], "--subject-id", subject_id], home)
    assert r.exit_code == 0, r.output
    obs_id = next(part for part in r.output.split() if part.startswith("OBS-"))
    r = _run(["claim", "add", "--text", "Host was compromised",
              "--observation", obs_id, "--subject-id", subject_id], home)
    assert r.exit_code == 0, r.output
    claim_id = next(part for part in r.output.split() if part.startswith("CLM-"))
    r = _run(["action", "create", "--type", "host-isolation",
              "--description", "Isolated host-01", "--claim", claim_id,
              "--subject-id", subject_id], home)
    assert r.exit_code == 0, r.output
    action_id = next(part for part in r.output.split() if part.startswith("ACT-"))

    r = _run([
        "decision", "create",
        "--type", "authorize-recovery",
        "--statement", "Authorize recovery for host-01",
        "--rationale", "Containment completed and evidence reviewed",
        "--decided-by", "lead@example.com",
        "--subject-id", subject_id,
        "--evidence", sha[:16],
        "--observation", obs_id,
        "--claim", claim_id,
        "--action", action_id,
        "--alternative", "Keep host isolated",
    ], home)
    assert r.exit_code == 0, r.output
    assert "DECISION" in r.output
    decision_id = next(part for part in r.output.split() if part.startswith("DEC-"))

    r = _run(["decision", "list"], home)
    assert r.exit_code == 0, r.output
    assert "1 decision(s)" in r.output

    r = _run(["decision", "show", decision_id], home)
    assert r.exit_code == 0, r.output
    assert "authorize-recovery" in r.output
    assert "Authorize recovery" in r.output
    assert "lead@example.com" in r.output
    assert claim_id in r.output

    r = _run([
        "decision", "amend", decision_id,
        "--statement", "Authorize staged recovery for host-01",
        "--reason", "Clarify scope",
    ], home)
    assert r.exit_code == 0, r.output
    assert "decision correction recorded" in r.output

    r = _run([
        "decision", "rationale", decision_id,
        "--rationale", "Containment completed and EDR telemetry reviewed",
        "--reason", "Add telemetry detail",
    ], home)
    assert r.exit_code == 0, r.output
    assert "decision rationale recorded" in r.output

    r = _run([
        "decision", "approve", decision_id,
        "--approved-by", "director@example.com",
        "--reason", "Recovery approved",
    ], home)
    assert r.exit_code == 0, r.output
    assert "decision approved" in r.output

    r = _run(["decision", "show", decision_id], home)
    assert r.exit_code == 0, r.output
    assert "DECISION AMENDMENTS" in r.output
    assert "director@example.com"[:12] in r.output

    r = _run([
        "decision", "create",
        "--type", "notify",
        "--statement", "Notify customer",
        "--rationale", "Customer impact confirmed",
        "--decided-by", "ai:assistant",
    ], home)
    assert r.exit_code == 1
    assert "human authority" in r.output

    r = _run(["timeline", "show"], home)
    assert r.exit_code == 0, r.output
    assert "decision-created" in r.output
    assert "decision-approved" in r.output


def test_decision_supersede_withdraw_and_reject_cli(tmp_path: Path):
    home = tmp_path / "incidents"
    r = _run(["declare", "--title", "Legal review", "--severity", "SEV3"], home)
    assert r.exit_code == 0, r.output
    first = _run([
        "decision", "create",
        "--type", "notify",
        "--statement", "Notify customer now",
        "--rationale", "Impact likely",
        "--decided-by", "lead",
    ], home)
    second = _run([
        "decision", "create",
        "--type", "notify",
        "--statement", "Delay notification",
        "--rationale", "Legal review pending",
        "--decided-by", "lead",
    ], home)
    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    first_id = next(part for part in first.output.split() if part.startswith("DEC-"))
    second_id = next(part for part in second.output.split() if part.startswith("DEC-"))

    r = _run(["decision", "supersede", first_id, "--by", second_id,
              "--reason", "Legal requested delay"], home)
    assert r.exit_code == 0, r.output
    assert "decision superseded" in r.output

    third = _run([
        "decision", "create",
        "--type", "closure",
        "--statement", "Close incident",
        "--rationale", "No impact found",
        "--decided-by", "lead",
    ], home)
    third_id = next(part for part in third.output.split() if part.startswith("DEC-"))
    r = _run(["decision", "withdraw", third_id, "--reason", "More evidence arrived"], home)
    assert r.exit_code == 0, r.output
    assert "decision withdrawn" in r.output

    fourth = _run([
        "decision", "create",
        "--type", "notify",
        "--statement", "Notify vendor",
        "--rationale", "Potential vendor impact",
        "--decided-by", "lead",
    ], home)
    fourth_id = next(part for part in fourth.output.split() if part.startswith("DEC-"))
    r = _run(["decision", "reject", fourth_id, "--reason", "No vendor impact"], home)
    assert r.exit_code == 0, r.output
    assert "decision rejected" in r.output


def test_graph_show_verify_and_json_export(tmp_path: Path):
    home = tmp_path / "incidents"
    ev = tmp_path / "edr.log"
    ev.write_text("host isolation telemetry\n", encoding="utf-8")

    r = _run(["declare", "--title", "Host compromise", "--severity", "SEV1"], home)
    assert r.exit_code == 0, r.output
    r = _run(["evidence", "add", "--file", str(ev), "--note", "EDR telemetry"], home)
    assert r.exit_code == 0, r.output
    r = _run(["subject", "create", "--type", "HOST", "--value", "host-01"], home)
    subject_id = next(part for part in r.output.split() if part.startswith("SUB-"))
    r = _run(["observe", "add", "--text", "EDR shows malware execution",
              "--subject-id", subject_id], home)
    obs_id = next(part for part in r.output.split() if part.startswith("OBS-"))
    r = _run(["claim", "add", "--text", "Host was compromised",
              "--observation", obs_id, "--subject-id", subject_id], home)
    claim_id = next(part for part in r.output.split() if part.startswith("CLM-"))
    r = _run(["action", "create", "--type", "host-isolation",
              "--description", "Isolated host-01", "--claim", claim_id,
              "--subject-id", subject_id], home)
    action_id = next(part for part in r.output.split() if part.startswith("ACT-"))
    r = _run(["decision", "create", "--type", "authorize-recovery",
              "--statement", "Authorize recovery", "--rationale", "Containment complete",
              "--decided-by", "lead", "--action", action_id,
              "--claim", claim_id, "--subject-id", subject_id], home)
    decision_id = next(part for part in r.output.split() if part.startswith("DEC-"))

    r = _run(["graph", "verify"], home)
    assert r.exit_code == 0, r.output
    assert "case graph verified" in r.output

    r = _run(["graph", "show"], home)
    assert r.exit_code == 0, r.output
    assert "CASE GRAPH" in r.output
    assert "RELATIONSHIPS" in r.output

    r = _run(["graph", "show", "--format", "json"], home)
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["summary"]["subject"] == 1
    assert data["summary"]["decision"] == 1
    assert any(edge["target"] == f"DECISION:{decision_id}" for edge in data["edges"])

    r = _run(["graph", "trace", decision_id, "--direction", "upstream", "--format", "json"], home)
    assert r.exit_code == 0, r.output
    trace = json.loads(r.output)
    assert trace["root"]["record_id"] == decision_id
    assert trace["direction"] == "upstream"
    assert any(node["record_id"] == obs_id for node in trace["nodes"])
    assert any(node["record_id"] == subject_id for node in trace["nodes"])

    r = _run(["graph", "trace", "CLM-MISSING"], home)
    assert r.exit_code == 1
    assert "record not found" in r.output


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
