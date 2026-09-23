"""CLI over signed trust-registry core semantics."""
import base64
import json
from pathlib import Path
from typing import Optional

import typer

from core.evidence.integrity import signing
from core.incident import IncidentWorkspace
from core.incident.snapshots import (_publish, _read, canonical_bytes, load_private_key,
                                     load_public_key, parse_json)
from core.incident.trust_registry import (
    TrustRegistryError, TrustRegistryStore, expected_tip_path, load_root_pin,
    make_key_record, releases_path, root_path, transition_keys, trust_health,
    write_root_pin,
)

app = typer.Typer(no_args_is_help=True, help="Signed trust-registry releases and key lifecycle.")
release_app = typer.Typer(no_args_is_help=True, help="Inspect and publish registry releases.")
key_app = typer.Typer(no_args_is_help=True, help="Manage public signing-key authorization.")
app.add_typer(release_app, name="release")
app.add_typer(key_app, name="key")


def _fail(message="INVALID: signed trust-registry operation failed."):
    typer.echo(message)
    raise typer.Exit(1)


def _home(value):
    return IncidentWorkspace.resolve_home(value)


def _store(home):
    root = _home(home)
    return TrustRegistryStore.discover(root)


def _root_private(path, home):
    return load_private_key(path, _home(home))


@app.command("init")
def init(registry_id: str = typer.Option(..., "--registry-id"),
         private_key: str = typer.Option(..., "--private-key"),
         actor: str = typer.Option(..., "--actor"),
         expected_tip: Optional[str] = typer.Option(None, "--expected-tip"),
         trust_reset_from: Optional[str] = typer.Option(None, "--trust-reset-from"),
         acknowledge_broken_continuity: bool = typer.Option(False, "--acknowledge-broken-continuity"),
         home: Optional[str] = typer.Option(None, "--home")):
    """Bootstrap a new root; trust reset requires explicit broken-continuity acknowledgement."""
    try:
        root = _home(home); private = Path(private_key).resolve()
        if private.is_relative_to(root):
            raise TrustRegistryError("registry private key must be outside Coreline home")
        if trust_reset_from and not acknowledge_broken_continuity:
            raise TrustRegistryError("trust reset acknowledgement required")
        key, public = signing.generate_signing_keypair()
        _publish(private, base64.b64encode(signing.encode_signing_key(key)))
        write_root_pin(root_path(root), registry_id, public, expected_tip)
        store = TrustRegistryStore(releases_path(root), load_root_pin(root_path(root)),
                                   expected_tip or expected_tip_path(root))
        reason = f"Explicit trust reset from {trust_reset_from}; cryptographic continuity not claimed" if trust_reset_from else None
        release = store.create_release(key, actor, [], kind="TRUST_RESET" if trust_reset_from else "BOOTSTRAP",
                                       reason=reason)
    except Exception:
        _fail()
    typer.echo(f"TRUST REGISTRY INITIALIZED {release['payload']['release_id']}")


@app.command("status")
def status(require_expected: bool = typer.Option(False, "--require-expected-tip"),
           home: Optional[str] = typer.Option(None, "--home")):
    result = trust_health(_home(home), require_expected=require_expected)
    typer.echo(json.dumps(result, sort_keys=True))
    if not result["valid"]:
        raise typer.Exit(1)


@release_app.command("list")
def release_list(home: Optional[str] = typer.Option(None, "--home")):
    try:
        store = _store(home); chain = store.verify_chain()
        if not chain["valid"]:
            raise TrustRegistryError()
        for path in store._paths():
            p = store.read(path.stem)["payload"]
            typer.echo(f"{p['generation']} {p['release_id']} {p['created_at']} {p['transition']['kind']}")
    except Exception:
        _fail()


@release_app.command("show")
def release_show(release_id: str, home: Optional[str] = typer.Option(None, "--home")):
    try:
        typer.echo(json.dumps(_store(home).read(release_id), sort_keys=True, indent=2))
    except Exception:
        _fail()


@release_app.command("verify")
def release_verify(require_expected: bool = typer.Option(False, "--require-expected-tip"),
                   home: Optional[str] = typer.Option(None, "--home")):
    result = _store(home).health(require_expected=require_expected)
    typer.echo(json.dumps(result, sort_keys=True))
    if not result["valid"]:
        raise typer.Exit(1)


@release_app.command("create")
def release_create(root_key: str = typer.Option(..., "--root-key"),
                   actor: str = typer.Option(..., "--actor"),
                   reason: Optional[str] = typer.Option(None, "--reason"),
                   home: Optional[str] = typer.Option(None, "--home")):
    try:
        store = _store(home); keys = store.latest_keys()
        document = store.create_release(_root_private(root_key, home), actor, keys,
                                        kind="UPDATE", reason=reason)
    except Exception:
        _fail()
    typer.echo(f"RELEASED {document['payload']['release_id']}")


def _public(path, home):
    return load_public_key(path, incident_dir=_home(home) / "incidents")


@key_app.command("list")
def key_list(home: Optional[str] = typer.Option(None, "--home")):
    try:
        keys = _store(home).latest_keys()
    except Exception:
        _fail()
    for item in keys:
        typer.echo(f"{item['key_id']} {item['purpose']} {item['scope']} {item['status']} {item['identity']}")


@key_app.command("add")
def key_add(public_key: str = typer.Option(..., "--public-key"),
            purpose: str = typer.Option(..., "--purpose"), scope: str = typer.Option(..., "--scope"),
            identity: str = typer.Option(..., "--identity"), root_key: str = typer.Option(..., "--root-key"),
            actor: str = typer.Option(..., "--actor"), home: Optional[str] = typer.Option(None, "--home")):
    try:
        store = _store(home); generation = store.verify_chain()["count"] + 1
        keys = store.latest_keys() + [make_key_record(_public(public_key, home), purpose.upper(), scope,
                                                      identity, generation)]
        document = store.create_release(_root_private(root_key, home), actor, keys, kind="UPDATE")
    except Exception:
        _fail()
    typer.echo(f"KEY ACTIVE {document['payload']['release_id']}")


@key_app.command("rotate")
def key_rotate(old_key_id: str = typer.Option(..., "--old-key-id"),
               public_key: str = typer.Option(..., "--public-key"), identity: str = typer.Option(..., "--identity"),
               reason: str = typer.Option(..., "--reason"), root_key: str = typer.Option(..., "--root-key"),
               actor: str = typer.Option(..., "--actor"), home: Optional[str] = typer.Option(None, "--home")):
    try:
        store = _store(home); generation = store.verify_chain()["count"] + 1
        old = store.key_record(old_key_id)
        if old is None:
            raise TrustRegistryError()
        keys = transition_keys(store.latest_keys(), old_key_id, "RETIRED", generation, reason)
        keys.append(make_key_record(_public(public_key, home), old["purpose"], old["scope"], identity, generation))
        document = store.create_release(_root_private(root_key, home), actor, keys,
                                        kind="ROTATION", reason=reason)
    except Exception:
        _fail()
    typer.echo(f"KEY ROTATED {document['payload']['release_id']}")


def _change(key_id, status, reason, root_key, actor, home):
    store = _store(home); generation = store.verify_chain()["count"] + 1
    keys = transition_keys(store.latest_keys(), key_id, status, generation, reason)
    return store.create_release(_root_private(root_key, home), actor, keys,
                                kind="REVOCATION" if status == "REVOKED" else "UPDATE", reason=reason)


@key_app.command("retire")
def key_retire(key_id: str = typer.Option(..., "--key-id"), reason: str = typer.Option(..., "--reason"),
               root_key: str = typer.Option(..., "--root-key"), actor: str = typer.Option(..., "--actor"),
               home: Optional[str] = typer.Option(None, "--home")):
    try: document = _change(key_id, "RETIRED", reason, root_key, actor, home)
    except Exception: _fail()
    typer.echo(f"KEY RETIRED {document['payload']['release_id']}")


@key_app.command("revoke")
def key_revoke(key_id: str = typer.Option(..., "--key-id"), reason: str = typer.Option(..., "--reason"),
               root_key: str = typer.Option(..., "--root-key"), actor: str = typer.Option(..., "--actor"),
               home: Optional[str] = typer.Option(None, "--home")):
    try: document = _change(key_id, "REVOKED", reason, root_key, actor, home)
    except Exception: _fail()
    typer.echo(f"KEY REVOKED {document['payload']['release_id']}")


@app.command("export")
def export_bundle(output: str = typer.Option(..., "--output"),
                  home: Optional[str] = typer.Option(None, "--home")):
    try:
        bundle = _store(home).export_bundle(); _publish(Path(output), canonical_bytes(bundle))
    except Exception: _fail()
    typer.echo("TRUST BUNDLE EXPORTED")


@app.command("import")
def import_bundle(bundle: str = typer.Option(..., "--bundle"),
                  home: Optional[str] = typer.Option(None, "--home")):
    try:
        document = _store(home).import_bundle(parse_json(_read(Path(bundle))))
    except Exception: _fail()
    typer.echo(f"TRUST BUNDLE IMPORTED {document['payload']['release_id']}")
