"""Thin CLI over core authenticated checkpoint APIs."""
from typing import Optional
import json

import typer

from core.incident import IncidentWorkspace, default_actor
from core.incident.snapshots import (
    SnapshotError, SnapshotStore, generate_key_files, load_private_key,
    load_public_key, public_key_path,
)

app = typer.Typer(no_args_is_help=True, help="Authenticated incident checkpoints.")


def _store(incident, home, key_path):
    root = IncidentWorkspace.resolve_home(home)
    ws = IncidentWorkspace.load(root, incident) if incident else IncidentWorkspace.load_current(root)
    key = None
    if key_path:
        key = load_public_key(key_path, incident_dir=ws.dir)
    return SnapshotStore(ws, key)


def _failure():
    typer.echo("INVALID: checkpoint operation failed (missing, malformed, untrusted, or inconsistent state).")
    raise typer.Exit(1)


@app.command("keygen")
def keygen(
    private_key: str = typer.Option(..., "--private-key", help="New private seed file outside the incident store."),
    public_key: Optional[str] = typer.Option(None, "--public-key", help="Public pin path; default home/trust/snapshot.verify.json."),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Provision a dedicated snapshot key; never overwrite existing keys."""
    root = IncidentWorkspace.resolve_home(home)
    try:
        fingerprint = generate_key_files(root, private_key, public_key or public_key_path(root))
    except Exception:
        _failure()
    typer.echo(f"Snapshot key: {fingerprint}")


@app.command("create")
def create(
    incident: Optional[str] = typer.Argument(None),
    signing_key: str = typer.Option(..., "--signing-key"),
    verify_key: Optional[str] = typer.Option(None, "--verify-key"),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Capture verified authoritative state without modifying its audit history."""
    try:
        store = _store(incident, home, verify_key)
        document = store.create(load_private_key(signing_key, store.ws.home), actor or default_actor())
    except Exception:
        _failure()
    typer.echo(f"VALID {document['payload']['snapshot_id']}")
    typer.echo(f"State digest: {document['payload']['incident_state_digest']}")


@app.command("list")
def list_snapshots(incident: Optional[str] = typer.Argument(None),
                   verify_key: Optional[str] = typer.Option(None, "--verify-key"),
                   home: Optional[str] = typer.Option(None, "--home")):
    try:
        store = _store(incident, home, verify_key)
        result = store.verify_chain()
        if not result["valid"]:
            _failure()
        documents = [store.read(path.stem)["payload"] for path in store._paths()]
    except Exception:
        _failure()
    typer.echo(result["status"])
    for p in sorted(documents, key=lambda p: p["sequence"]):
        typer.echo(f"{p['sequence']} {p['snapshot_id']} {p['created_at']} final={p['final']}")


@app.command("show")
def show(incident: str, snapshot_id: str, home: Optional[str] = typer.Option(None, "--home")):
    """Print the portable envelope; display alone is not verification."""
    try:
        document = _store(incident, home, None).read(snapshot_id)
    except Exception:
        _failure()
    typer.echo(json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False))


@app.command("verify")
def verify(incident: str, snapshot_id: str,
           verify_key: Optional[str] = typer.Option(None, "--verify-key"),
           home: Optional[str] = typer.Option(None, "--home")):
    """Verify one historical signature using only public verification material."""
    try:
        result = _store(incident, home, verify_key).verify_snapshot(snapshot_id)
    except Exception:
        _failure()
    typer.echo(json.dumps(result, sort_keys=True))
    typer.echo("VALID" if result["valid"] else "INVALID / SIGNATURE INVALID")
    if not result["valid"]:
        raise typer.Exit(1)


@app.command("verify-chain")
def verify_chain(incident: Optional[str] = typer.Argument(None),
                 expected_tip: Optional[str] = typer.Option(None, "--expected-tip", help="Independently retained tip ID or digest."),
                 verify_key: Optional[str] = typer.Option(None, "--verify-key"),
                 home: Optional[str] = typer.Option(None, "--home")):
    try:
        result = _store(incident, home, verify_key).verify_chain(expected_tip)
    except Exception:
        _failure()
    typer.echo(result["status"])
    if not result["valid"]:
        typer.echo("CHAIN BROKEN")
        raise typer.Exit(1)


@app.command("compare-current")
def compare_current(incident: str, snapshot_id: str,
                    verify_key: Optional[str] = typer.Option(None, "--verify-key"),
                    home: Optional[str] = typer.Option(None, "--home")):
    try:
        result = _store(incident, home, verify_key).compare_current(snapshot_id)
    except Exception:
        _failure()
    typer.echo(json.dumps(result, sort_keys=True))
    typer.echo("CURRENT STATE MATCHES" if result["current_state_matches"] else "CURRENT STATE DIFFERS")
    if result["missing"]:
        typer.echo("RECORD MISSING")
    if result["modified"]:
        typer.echo("RECORD MODIFIED")
    if not result["current_state_matches"]:
        raise typer.Exit(1)


@app.command("report")
def report(incident: Optional[str] = typer.Argument(None),
           verify_key: Optional[str] = typer.Option(None, "--verify-key"),
           home: Optional[str] = typer.Option(None, "--home")):
    """Render live checkpoint attestation, including for sealed incidents."""
    try:
        store = _store(incident, home, verify_key)
        result = store.ws.snapshot_report(verify_key=store.key) + "\n" + store.ws.anchor_report(
            snapshot_verify_key=store.key)
        valid = store.health()["valid"] and store.ws.anchor_health(
            snapshot_verify_key=store.key)["valid"]
    except Exception:
        _failure()
    typer.echo(result)
    if not valid:
        raise typer.Exit(1)
