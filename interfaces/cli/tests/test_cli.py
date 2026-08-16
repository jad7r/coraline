"""Smoke tests for the Typer CLI surface via CliRunner (no real terminal needed)."""
from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from interfaces.cli.coreline import app

runner = CliRunner()


def _run(args, home: Path):
    return runner.invoke(app, args, env={"CORELINE_HOME": str(home), "CORELINE_ACTOR": "tester"})


def test_help_lists_all_commands():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    for cmd in ("declare", "doctor", "evidence", "timeline", "status", "report", "use", "close", "verify"):
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
