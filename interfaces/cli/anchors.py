"""Thin CLI for independent snapshot anchor receipts."""
import base64
import json
from pathlib import Path
from typing import Optional

import typer

from core.evidence.integrity import signing
from core.incident import IncidentWorkspace
from core.incident.anchors import (
    AnchorError, AnchorManager, _publish, canonical_bytes, load_registry,
    registry_path, write_registry,
)
from core.incident.snapshots import load_private_key, load_public_key

app = typer.Typer(no_args_is_help=True, help="Independent snapshot acknowledgements.")


def _fail(message="INVALID: anchor operation failed or trust could not be established."):
    typer.echo(message)
    raise typer.Exit(1)


def _workspace(home, incident):
    root = IncidentWorkspace.resolve_home(home)
    return IncidentWorkspace.load(root, incident) if incident else IncidentWorkspace.load_current(root)


def _config(ws, path):
    return load_registry(path or registry_path(ws.home), incident_dir=ws.dir)


@app.command("init")
def init(anchor_id: str = typer.Option(..., "--anchor-id"),
         root: str = typer.Option(..., "--root", help="New ledger directory outside the incident store."),
         private_key: str = typer.Option(..., "--private-key", help="New anchor private key outside the Coreline home."),
         policy: str = typer.Option("OPTIONAL", "--policy"),
         registry: Optional[str] = typer.Option(None, "--registry"),
         home: Optional[str] = typer.Option(None, "--home")):
    """Create one filesystem anchor trust configuration without overwriting files."""
    try:
        home_path = IncidentWorkspace.resolve_home(home)
        root_path, private_path = Path(root).resolve(), Path(private_key).resolve()
        if root_path.is_relative_to(home_path) or private_path.is_relative_to(home_path):
            raise AnchorError("anchor storage and private key must be outside Coreline home")
        key, public = signing.generate_signing_keypair()
        _publish(private_path, base64.b64encode(signing.encode_signing_key(key)))
        write_registry(registry or registry_path(home_path), anchor_id, root_path, public, policy.upper())
    except Exception:
        _fail()
    typer.echo(f"ANCHOR CONFIGURED {anchor_id}")


@app.command("snapshot")
def anchor_snapshot(incident: str, snapshot_id: str,
                    signing_key: str = typer.Option(..., "--signing-key"),
                    registry: Optional[str] = typer.Option(None, "--registry"),
                    snapshot_verify_key: Optional[str] = typer.Option(None, "--snapshot-verify-key"),
                    home: Optional[str] = typer.Option(None, "--home")):
    try:
        ws = _workspace(home, incident)
        config = _config(ws, registry)
        snapshot_key = load_public_key(snapshot_verify_key, incident_dir=ws.dir) if snapshot_verify_key else None
        receipt = ws.anchor_snapshot(snapshot_id, load_private_key(signing_key, ws.home),
                                     anchor_config=config, snapshot_verify_key=snapshot_key)
    except Exception:
        _fail()
    typer.echo(f"ANCHORED {snapshot_id}")
    typer.echo(f"Receipt: {receipt['payload']['receipt_id']}")


@app.command("list")
def list_receipts(incident: Optional[str] = typer.Argument(None),
                  registry: Optional[str] = typer.Option(None, "--registry"),
                  home: Optional[str] = typer.Option(None, "--home")):
    try:
        ws = _workspace(home, incident)
        manager = AnchorManager(ws, _config(ws, registry), online=False)
        receipts = manager.list_receipts()
        for receipt in receipts:
            p = receipt["payload"]
            typer.echo(f"{p['anchor_sequence']} {p['receipt_id']} {p['snapshot_id']}")
    except Exception:
        _fail()


@app.command("show")
def show(incident: str, receipt_id: str, registry: Optional[str] = typer.Option(None, "--registry"),
         home: Optional[str] = typer.Option(None, "--home")):
    try:
        ws = _workspace(home, incident)
        manager = AnchorManager(ws, _config(ws, registry), online=False)
        receipt = manager.get_receipt(receipt_id)
    except Exception:
        _fail()
    typer.echo(json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=False))


@app.command("verify")
def verify(incident: str, receipt_id: str, registry: Optional[str] = typer.Option(None, "--registry"),
           home: Optional[str] = typer.Option(None, "--home")):
    try:
        ws = _workspace(home, incident)
        manager = AnchorManager(ws, _config(ws, registry), online=False)
        result = manager.verify_anchor_receipt(receipt_id)
    except Exception:
        _fail()
    typer.echo(json.dumps(result, sort_keys=True))
    typer.echo("OFFLINE RECEIPT VERIFIED" if result["valid"] else "RECEIPT INVALID")
    if not result["valid"]:
        raise typer.Exit(1)


def _status(incident, registry, home, online):
    ws = _workspace(home, incident)
    return AnchorManager(ws, _config(ws, registry), online=online).health()


@app.command("expected-tip")
def expected_tip(incident: Optional[str] = typer.Argument(None),
                 registry: Optional[str] = typer.Option(None, "--registry"),
                 home: Optional[str] = typer.Option(None, "--home")):
    try:
        result = _status(incident, registry, home, True)
    except Exception:
        _fail("ANCHOR UNAVAILABLE")
    typer.echo(f"Expected relation: {result['expected_tip_relation']}")
    typer.echo(f"Snapshot: {result.get('anchored_snapshot_id')}")
    if not result["expected_tip_checked"]:
        _fail("ANCHOR UNAVAILABLE")


@app.command("verify-tip")
def verify_tip(incident: Optional[str] = typer.Argument(None),
               registry: Optional[str] = typer.Option(None, "--registry"),
               home: Optional[str] = typer.Option(None, "--home")):
    try:
        result = _status(incident, registry, home, True)
    except Exception:
        _fail()
    typer.echo(result["expected_tip_relation"])
    if result["expected_tip_relation"] == "MATCH":
        typer.echo("EXPECTED TIP MATCHES")
    elif result["expected_tip_relation"] == "LOCAL_AHEAD_OF_EXPECTED":
        typer.echo("LOCAL AHEAD OF EXPECTED TIP")
    elif result["expected_tip_relation"] == "LOCAL_BEHIND_EXPECTED":
        typer.echo("LOCAL BEHIND EXPECTED TIP")
    else:
        typer.echo("EXPECTED TIP VERIFICATION FAILED")
    if not result["valid"]:
        raise typer.Exit(1)


@app.command("status")
def status(incident: Optional[str] = typer.Argument(None), offline: bool = typer.Option(False, "--offline"),
           registry: Optional[str] = typer.Option(None, "--registry"),
           home: Optional[str] = typer.Option(None, "--home")):
    try:
        result = _status(incident, registry, home, not offline)
    except Exception:
        _fail()
    typer.echo(json.dumps(result, sort_keys=True))
    if not result["valid"]:
        raise typer.Exit(1)
