"""
coreline — the Coreline incident-response operator CLI.

A polished, dark-mode SecOps terminal front-end (Typer + Rich) over the deterministic
``core`` package. Run a live incident end to end on a laptop, no network, no AI:

    python -m interfaces.cli.coreline declare --title "DB Exfiltration Alert" --severity SEV1
    python -m interfaces.cli.coreline evidence add --file alert.log --note "SIEM alert"
    python -m interfaces.cli.coreline timeline show
    python -m interfaces.cli.coreline status
    python -m interfaces.cli.coreline report

Crypto-bearing operations (SHA-256, Ed25519 manifest signing, chain of custody,
write-only storage), incident state, and the hash-linked audit log run through the
tested ``core`` layer.
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
from rich import box

from core.incident import (
    Action,
    ActionAmendment,
    ACTION_STATUSES,
    Claim,
    ClaimAmendment,
    CLAIM_STATUSES,
    IncidentWorkspace,
    OBSERVATION_DISPOSITIONS,
    Observation,
    ObservationAmendment,
    WorkspaceError,
    SEVERITIES,
    default_actor,
)
from core.evidence.integrity import signing
from core.evidence.registry import (
    RegistryError,
    TrustedSignerRegistry,
    load_registry,
    load_signed_registry,
    save_registry,
    seal_registry,
    verify_registry_seal,
)
from core.evidence.seal import load_seal, write_seal

# ---- theme ------------------------------------------------------------------- #

console = Console()

C_ACCENT = "bold cyan"
C_OK = "bold green"
C_BAD = "bold red"
C_WARN = "bold yellow"
C_DIM = "grey58"

SEV_STYLE = {
    "SEV1": "bold white on red",
    "SEV2": "bold red",
    "SEV3": "bold yellow",
    "SEV4": "cyan",
    "SEV5": "grey58",
}
STATUS_STYLE = {
    "OPEN": "bold yellow",
    "DECLARED": "bold yellow",
    "INVESTIGATING": "bold cyan",
    "CONTAINED": "bold blue",
    "ERADICATING": "bold magenta",
    "RECOVERING": "bold white",
    "RESOLVED": "bold green",
    "CLOSED": "grey58",
    "SEALED": "bold white on grey23",
}

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Coreline — deterministic incident-response console.",
    rich_markup_mode="rich",
)
evidence_app = typer.Typer(no_args_is_help=True, help="Evidence collection & integrity.")
timeline_app = typer.Typer(no_args_is_help=True, help="Incident timeline.")
registry_app = typer.Typer(no_args_is_help=True, help="Trusted signer registry.")
lifecycle_app = typer.Typer(no_args_is_help=True, help="Incident lifecycle transitions.")
observe_app = typer.Typer(no_args_is_help=True, help="Investigative observations.")
claim_app = typer.Typer(no_args_is_help=True, help="Investigative claims.")
action_app = typer.Typer(no_args_is_help=True, help="Responder actions.")
app.add_typer(evidence_app, name="evidence")
app.add_typer(timeline_app, name="timeline")
app.add_typer(registry_app, name="registry")
app.add_typer(lifecycle_app, name="lifecycle")
app.add_typer(observe_app, name="observe")
app.add_typer(claim_app, name="claim")
app.add_typer(action_app, name="action")


# ---- shared helpers ---------------------------------------------------------- #

def _home(home_opt: Optional[str]) -> Path:
    return IncidentWorkspace.resolve_home(home_opt)


def _load(home_opt: Optional[str], incident_id: Optional[str]) -> IncidentWorkspace:
    home = _home(home_opt)
    try:
        if incident_id:
            return IncidentWorkspace.load(home, incident_id)
        return IncidentWorkspace.load_current(home)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)


def _banner() -> None:
    art = Text()
    art.append("  CORELINE\n", style=C_ACCENT)
    art.append("  deterministic incident-response console", style=C_DIM)
    console.print(Panel(art, border_style="cyan", box=box.HEAVY, padding=(0, 2)))


def _sev(sev: str) -> Text:
    return Text(f" {sev} ", style=SEV_STYLE.get(sev, "white"))


def _status(st: str) -> Text:
    return Text(st, style=STATUS_STYLE.get(st, "white"))


def _evidence_refs(evidence: tuple[str, ...]) -> str:
    return ", ".join(sha[:12] + "…" for sha in evidence) if evidence else "none"


def _observation_panel(obs: Observation) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("observation", Text(obs.observation_id, style=C_ACCENT))
    table.add_row("incident", obs.incident_id)
    table.add_row("created", obs.created_at)
    table.add_row("creator", obs.creator)
    table.add_row("disposition", obs.disposition)
    if obs.subject:
        table.add_row("subject", obs.subject)
    table.add_row("evidence", _evidence_refs(obs.evidence))
    table.add_row("text", obs.text)
    return Panel(table, title="[bold]OBSERVATION[/]", border_style="cyan",
                 box=box.ROUNDED)


def _claim_refs(observations: tuple[str, ...]) -> str:
    return ", ".join(observations) if observations else "none"


def _claim_refs_short(observations: tuple[str, ...]) -> str:
    return ", ".join(obs[:12] for obs in observations) if observations else "none"


def _claim_panel(
    claim: Claim,
    current_status: Optional[str] = None,
    current_text: Optional[str] = None,
) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("claim", Text(claim.claim_id, style=C_ACCENT))
    table.add_row("incident", claim.incident_id)
    table.add_row("created", claim.created_at)
    table.add_row("creator", claim.creator)
    table.add_row("status", current_status or claim.status)
    if claim.subject:
        table.add_row("subject", claim.subject)
    table.add_row("observations", _claim_refs(claim.observations))
    table.add_row("text", current_text or claim.text)
    if current_text and current_text != claim.text:
        table.add_row("original text", claim.text)
    return Panel(table, title="[bold]CLAIM[/]", border_style="cyan",
                 box=box.ROUNDED)


def _claim_amendment_rows(table: Table, amendments: List[ClaimAmendment]) -> None:
    for amendment in amendments:
        table.add_row(
            amendment.amendment_id,
            amendment.created_at.replace("T", " ")[:19],
            amendment.amendment_type,
            amendment.status or "",
            amendment.text,
            amendment.reason or "",
        )


def _action_refs(values: tuple[str, ...], *, short: bool = False) -> str:
    if not values:
        return "none"
    if short:
        return ", ".join(value[:12] for value in values)
    return ", ".join(values)


def _action_panel(
    action: Action,
    current_status: Optional[str] = None,
    current_description: Optional[str] = None,
    current_outcome: Optional[str] = None,
) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("action", Text(action.action_id, style=C_ACCENT))
    table.add_row("incident", action.incident_id)
    table.add_row("created", action.created_at)
    table.add_row("actor", action.actor)
    table.add_row("type", action.action_type)
    table.add_row("status", current_status or action.status)
    if action.subject:
        table.add_row("subject", action.subject)
    table.add_row("claims", _action_refs(action.claims))
    table.add_row("observations", _action_refs(action.observations))
    table.add_row("evidence", _evidence_refs(action.evidence))
    table.add_row("description", current_description or action.description)
    if current_description and current_description != action.description:
        table.add_row("original description", action.description)
    outcome = current_outcome if current_outcome is not None else action.outcome
    if outcome:
        table.add_row("outcome", outcome)
    return Panel(table, title="[bold]ACTION[/]", border_style="cyan",
                 box=box.ROUNDED)


def _action_amendment_rows(table: Table, amendments: List[ActionAmendment]) -> None:
    for amendment in amendments:
        table.add_row(
            amendment.amendment_id,
            amendment.created_at.replace("T", " ")[:19],
            amendment.amendment_type,
            amendment.status or "",
            amendment.text,
            amendment.outcome or "",
            amendment.reason or "",
        )


def _amendment_rows(table: Table, amendments: List[ObservationAmendment]) -> None:
    for amendment in amendments:
        table.add_row(
            amendment.amendment_id,
            amendment.created_at.replace("T", " ")[:19],
            amendment.amendment_type,
            amendment.text,
            amendment.reason or "",
        )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _registry_path(home: Path, registry: Optional[str]) -> Path:
    return Path(registry).resolve() if registry else home / "trust" / "registry.json"


def _registry_seal_path(registry_path: Path, seal: Optional[str]) -> Path:
    return Path(seal).resolve() if seal else Path(f"{registry_path}.seal.json")


def _root_key_path(home: Path, root_key: Optional[str]) -> Path:
    return Path(root_key).resolve() if root_key else home / "trust" / "root.key"


def _root_verify_path(home: Path, root_verify: Optional[str]) -> Path:
    return Path(root_verify).resolve() if root_verify else home / "trust" / "root.verify.json"


def _write_root_key(path: Path, sk) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        base64.b64encode(signing.encode_signing_key(sk)).decode("ascii"),
        encoding="utf-8",
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _read_root_key(path: Path):
    raw = base64.b64decode(path.read_text(encoding="utf-8").strip())
    return signing.decode_signing_key(raw)


def _write_root_verify(path: Path, vk) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "verify_key": signing.encode_verify_key(vk),
                "fingerprint": signing.key_fingerprint(vk),
                "algorithm": "ed25519",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _read_root_verify(path: Path):
    info = json.loads(path.read_text(encoding="utf-8"))
    return signing.decode_verify_key(info["verify_key"]), info


# ---- declare ----------------------------------------------------------------- #

@app.command()
def declare(
    title: str = typer.Option(..., "--title", "-t", help="Human-readable incident title."),
    severity: str = typer.Option(..., "--severity", "-s",
                                 help=f"One of {', '.join(SEVERITIES)}."),
    actor: Optional[str] = typer.Option(None, "--actor", help="Responder identity."),
    home: Optional[str] = typer.Option(None, "--home", help="Incident store root."),
):
    """Declare a new incident: mint an ID, start the signed manifest + audit log."""
    who = actor or default_actor()
    try:
        ws = IncidentWorkspace.declare(_home(home), title=title, severity=severity,
                                       actor=who)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)

    _banner()
    body = Table.grid(padding=(0, 2))
    body.add_column(style=C_DIM, justify="right")
    body.add_column()
    body.add_row("incident", Text(ws.incident_id, style=C_ACCENT))
    body.add_row("title", ws.state["title"])
    body.add_row("severity", _sev(ws.state["severity"]))
    body.add_row("status", _status(ws.state["status"]))
    body.add_row("declared", ws.state["created_at"])
    body.add_row("lead", who)
    _, info = ws._read_verify_key()
    body.add_row("signer", Text(info["fingerprint"], style=C_DIM))
    console.print(Panel(body, title="[bold]INCIDENT DECLARED[/]", border_style="green",
                        box=box.ROUNDED))
    console.print(f"[{C_DIM}]now the active incident — subsequent commands target it "
                  f"(or pass --id {ws.incident_id}).[/]")


# ---- evidence add ------------------------------------------------------------ #

@evidence_app.command("add")
def evidence_add(
    file: Path = typer.Option(..., "--file", "-f", exists=False,
                              help="Path to the evidence file."),
    note: str = typer.Option("", "--note", "-n", help="Analyst note for the custody record."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Hash a file (SHA-256), deposit an immutable copy, seal + sign the manifest."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        res = ws.add_evidence(str(file), note, who)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)

    t = Table.grid(padding=(0, 2))
    t.add_column(style=C_DIM, justify="right")
    t.add_column()
    t.add_row("file", file.name)
    t.add_row("size", f"{res['size']} bytes")
    t.add_row("sha-256", Text(res["sha256"], style=C_OK))
    t.add_row("stored", Text(res["receipt"].uri, style=C_DIM))
    t.add_row("manifest hash", Text(res["manifest_hash"], style=C_ACCENT))
    t.add_row("evidence count", str(res["evidence_count"]))
    if note:
        t.add_row("note", note)
    console.print(Panel(t, title="[bold]EVIDENCE SEALED[/]", border_style="cyan",
                        box=box.ROUNDED))


# ---- observations ---------------------------------------------------------- #

@observe_app.command("add")
def observe_add(
    text: str = typer.Option(..., "--text", "-t", help="Observation text."),
    evidence: Optional[List[str]] = typer.Option(
        None,
        "--evidence",
        "-e",
        help="Evidence SHA-256 or unique prefix from this incident manifest.",
    ),
    disposition: str = typer.Option(
        "OBSERVED",
        "--disposition",
        "-d",
        help=f"One of {', '.join(OBSERVATION_DISPOSITIONS)}.",
    ),
    subject: Optional[str] = typer.Option(None, "--subject", "-s",
                                          help="Optional investigated subject."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Record an immutable investigative observation linked to evidence hashes."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        obs = ws.add_observation(
            text=text,
            actor=who,
            evidence_refs=evidence or [],
            disposition=disposition,
            subject=subject,
        )
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(_observation_panel(obs))


@observe_app.command("list")
def observe_list(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """List investigative observations for an incident."""
    ws = _load(home, incident_id)
    observations = ws.observations()
    table = Table(
        title=f"[bold]OBSERVATIONS[/]  {ws.incident_id}",
        box=box.SIMPLE_HEAVY,
        header_style=C_ACCENT,
        border_style="cyan",
        pad_edge=False,
    )
    table.add_column("id", style=C_ACCENT, no_wrap=True)
    table.add_column("created", style=C_DIM, no_wrap=True)
    table.add_column("disposition", no_wrap=True)
    table.add_column("evidence", style=C_DIM)
    table.add_column("observation", overflow="fold", ratio=1)
    for obs in observations:
        effective = ws.effective_observation(obs.observation_id)
        table.add_row(
            obs.observation_id,
            obs.created_at.replace("T", " ")[:19],
            effective.current_status,
            _evidence_refs(obs.evidence),
            effective.current_text,
        )
    console.print(table)
    console.print(f"[{C_DIM}]{len(observations)} observation(s)[/]")


@observe_app.command("show")
def observe_show(
    observation_id: str = typer.Argument(..., help="Observation ID."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Show one investigative observation."""
    ws = _load(home, incident_id)
    try:
        obs = ws.observation(observation_id)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(_observation_panel(obs))
    amendments = ws.observation_amendments(observation_id)
    if amendments:
        table = Table(
            title=f"[bold]AMENDMENTS[/]  {observation_id}",
            box=box.SIMPLE_HEAVY,
            header_style=C_ACCENT,
            border_style="cyan",
            pad_edge=False,
        )
        table.add_column("id", style=C_ACCENT, no_wrap=True)
        table.add_column("created", style=C_DIM, no_wrap=True)
        table.add_column("type", no_wrap=True)
        table.add_column("text", overflow="fold", ratio=1)
        table.add_column("reason", overflow="fold", ratio=1)
        _amendment_rows(table, amendments)
        console.print(table)


@observe_app.command("correct")
def observe_correct(
    observation_id: str = typer.Argument(..., help="Observation ID."),
    correction: str = typer.Option(..., "--text", "-t", help="Correction text."),
    reason: Optional[str] = typer.Option(None, "--reason", "-r", help="Optional correction reason."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Append a correction to an immutable observation."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        amendment = ws.correct_observation(observation_id, correction, who, reason=reason)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ correction recorded[/] {amendment.amendment_id}")


@observe_app.command("retract")
def observe_retract(
    observation_id: str = typer.Argument(..., help="Observation ID."),
    reason: str = typer.Option(..., "--reason", "-r", help="Retraction reason."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Append a retraction to an immutable observation."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        amendment = ws.retract_observation(observation_id, reason, who)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ retraction recorded[/] {amendment.amendment_id}")


# ---- claims ---------------------------------------------------------------- #

@claim_app.command("add")
def claim_add(
    text: str = typer.Option(..., "--text", "-t", help="Claim text."),
    observation: List[str] = typer.Option(
        ...,
        "--observation",
        "-o",
        help="Supporting observation ID from this incident.",
    ),
    status: str = typer.Option(
        "ASSERTED",
        "--status",
        "-s",
        help=f"One of {', '.join(CLAIM_STATUSES)}.",
    ),
    subject: Optional[str] = typer.Option(None, "--subject", help="Optional investigated subject."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Record an immutable claim supported by observation records."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        claim = ws.add_claim(
            text=text,
            actor=who,
            observation_refs=observation,
            status=status,
            subject=subject,
        )
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(_claim_panel(claim))


@claim_app.command("list")
def claim_list(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """List investigative claims for an incident."""
    ws = _load(home, incident_id)
    claims = ws.claims()
    table = Table(
        title=f"[bold]CLAIMS[/]  {ws.incident_id}",
        box=box.SIMPLE_HEAVY,
        header_style=C_ACCENT,
        border_style="cyan",
        pad_edge=False,
    )
    table.add_column("id", style=C_ACCENT, no_wrap=True)
    table.add_column("created", style=C_DIM, no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("support", style=C_DIM, no_wrap=True)
    table.add_column("claim", overflow="fold", ratio=1)
    for claim in claims:
        effective = ws.effective_claim(claim.claim_id)
        table.add_row(
            claim.claim_id,
            claim.created_at.replace("T", " ")[:19],
            effective.current_status,
            _claim_refs_short(claim.observations),
            effective.current_text,
        )
    console.print(table)
    console.print(f"[{C_DIM}]{len(claims)} claim(s)[/]")


@claim_app.command("show")
def claim_show(
    claim_id: str = typer.Argument(..., help="Claim ID."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Show one investigative claim."""
    ws = _load(home, incident_id)
    try:
        claim = ws.claim(claim_id)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    effective = ws.effective_claim(claim_id)
    console.print(_claim_panel(claim, effective.current_status, effective.current_text))
    amendments = ws.claim_amendments(claim_id)
    if amendments:
        table = Table(
            title=f"[bold]CLAIM AMENDMENTS[/]  {claim_id}",
            box=box.SIMPLE_HEAVY,
            header_style=C_ACCENT,
            border_style="cyan",
            pad_edge=False,
        )
        table.add_column("id", style=C_ACCENT, no_wrap=True)
        table.add_column("created", style=C_DIM, no_wrap=True)
        table.add_column("type", no_wrap=True)
        table.add_column("status", no_wrap=True)
        table.add_column("text", overflow="fold", ratio=1)
        table.add_column("reason", overflow="fold", ratio=1)
        _claim_amendment_rows(table, amendments)
        console.print(table)


@claim_app.command("correct")
def claim_correct(
    claim_id: str = typer.Argument(..., help="Claim ID."),
    correction: str = typer.Option(..., "--text", "-t", help="Correction text."),
    reason: Optional[str] = typer.Option(None, "--reason", "-r", help="Optional correction reason."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Append a correction to an immutable claim."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        amendment = ws.correct_claim(claim_id, correction, who, reason=reason)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ claim correction recorded[/] {amendment.amendment_id}")


@claim_app.command("status")
def claim_status(
    claim_id: str = typer.Argument(..., help="Claim ID."),
    status: str = typer.Option(..., "--status", "-s", help=f"One of {', '.join(CLAIM_STATUSES)}."),
    reason: str = typer.Option(..., "--reason", "-r", help="Reason for the status change."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Append a status update to an immutable claim."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        amendment = ws.update_claim_status(claim_id, status, who, reason)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ claim status recorded[/] {amendment.amendment_id}")


@claim_app.command("withdraw")
def claim_withdraw(
    claim_id: str = typer.Argument(..., help="Claim ID."),
    reason: str = typer.Option(..., "--reason", "-r", help="Withdrawal reason."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Append a withdrawal to an immutable claim."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        amendment = ws.withdraw_claim(claim_id, reason, who)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ claim withdrawal recorded[/] {amendment.amendment_id}")


# ---- actions --------------------------------------------------------------- #

@action_app.command("create")
def action_create(
    action_type: str = typer.Option(..., "--type", "-t", help="Action type, e.g. credential-revocation."),
    description: str = typer.Option(..., "--description", "-d", help="What the responder did or plans to do."),
    status: str = typer.Option("PLANNED", "--status", "-s", help=f"One of {', '.join(ACTION_STATUSES)}."),
    subject: Optional[str] = typer.Option(None, "--subject", help="Optional affected user, host, system, or account."),
    claim: Optional[List[str]] = typer.Option(None, "--claim", "-c", help="Supporting claim ID."),
    observation: Optional[List[str]] = typer.Option(None, "--observation", "-o", help="Supporting observation ID."),
    evidence: Optional[List[str]] = typer.Option(None, "--evidence", "-e", help="Supporting evidence SHA-256 or prefix."),
    outcome: Optional[str] = typer.Option(None, "--outcome", help="Optional initial action outcome."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Record an immutable responder action."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        action = ws.create_action(
            action_type=action_type,
            description=description,
            actor=who,
            status=status,
            subject=subject,
            claim_refs=claim or [],
            observation_refs=observation or [],
            evidence_refs=evidence or [],
            outcome=outcome,
        )
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(_action_panel(action))


@action_app.command("list")
def action_list(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """List responder actions for an incident."""
    ws = _load(home, incident_id)
    actions = ws.actions()
    table = Table(
        title=f"[bold]ACTIONS[/]  {ws.incident_id}",
        box=box.SIMPLE_HEAVY,
        header_style=C_ACCENT,
        border_style="cyan",
        pad_edge=False,
    )
    table.add_column("id", style=C_ACCENT, no_wrap=True)
    table.add_column("created", style=C_DIM, no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("type", no_wrap=True)
    table.add_column("refs", style=C_DIM, no_wrap=True)
    table.add_column("action", overflow="fold", ratio=1)
    for action in actions:
        effective = ws.effective_action(action.action_id)
        refs = []
        refs.extend(action.claims)
        refs.extend(action.observations)
        refs.extend(sha[:12] for sha in action.evidence)
        table.add_row(
            action.action_id[:12],
            action.created_at.replace("T", " ")[:19],
            effective.current_status,
            action.action_type,
            ", ".join(refs) if refs else "none",
            effective.current_description,
        )
    console.print(table)
    if actions:
        console.print(
            f"[{C_DIM}]ids: "
            f"{', '.join(f'{action.action_id[:12]} ({action.action_type})' for action in actions)}[/]"
        )
    console.print(f"[{C_DIM}]{len(actions)} action(s)[/]")


@action_app.command("show")
def action_show(
    action_id: str = typer.Argument(..., help="Action ID."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Show one responder action."""
    ws = _load(home, incident_id)
    try:
        action = ws.action(action_id)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    effective = ws.effective_action(action_id)
    console.print(_action_panel(
        action,
        effective.current_status,
        effective.current_description,
        effective.current_outcome,
    ))
    amendments = ws.action_amendments(action_id)
    if amendments:
        table = Table(
            title=f"[bold]ACTION AMENDMENTS[/]  {action_id}",
            box=box.SIMPLE_HEAVY,
            header_style=C_ACCENT,
            border_style="cyan",
            pad_edge=False,
        )
        table.add_column("id", style=C_ACCENT, no_wrap=True)
        table.add_column("created", style=C_DIM, no_wrap=True)
        table.add_column("type", no_wrap=True)
        table.add_column("status", no_wrap=True)
        table.add_column("text", overflow="fold", ratio=1)
        table.add_column("outcome", overflow="fold", ratio=1)
        table.add_column("reason", overflow="fold", ratio=1)
        _action_amendment_rows(table, amendments)
        console.print(table)


@action_app.command("amend")
def action_amend(
    action_id: str = typer.Argument(..., help="Action ID."),
    correction: str = typer.Option(..., "--description", "-d", help="Corrected action description."),
    reason: Optional[str] = typer.Option(None, "--reason", "-r", help="Optional correction reason."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Append a correction to an immutable action."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        amendment = ws.amend_action(action_id, correction, who, reason=reason)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ action correction recorded[/] {amendment.amendment_id}")


@action_app.command("status")
def action_status(
    action_id: str = typer.Argument(..., help="Action ID."),
    status: str = typer.Option(..., "--status", "-s", help=f"One of {', '.join(ACTION_STATUSES)} except CANCELLED."),
    reason: str = typer.Option(..., "--reason", "-r", help="Reason for the status change."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Append a status update to an immutable action."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        amendment = ws.update_action_status(action_id, status, who, reason)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ action status recorded[/] {amendment.amendment_id}")


@action_app.command("outcome")
def action_outcome(
    action_id: str = typer.Argument(..., help="Action ID."),
    outcome: str = typer.Option(..., "--outcome", "-o", help="Action outcome."),
    reason: Optional[str] = typer.Option(None, "--reason", "-r", help="Optional outcome update reason."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Append an outcome update to an immutable action."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        amendment = ws.update_action_outcome(action_id, outcome, who, reason=reason)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ action outcome recorded[/] {amendment.amendment_id}")


@action_app.command("cancel")
def action_cancel(
    action_id: str = typer.Argument(..., help="Action ID."),
    reason: str = typer.Option(..., "--reason", "-r", help="Cancellation reason."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Append a cancellation to an immutable action."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        amendment = ws.cancel_action(action_id, reason, who)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ action cancellation recorded[/] {amendment.amendment_id}")


# ---- lifecycle -------------------------------------------------------------- #

def _transition(
    target: str,
    incident_id: Optional[str],
    note: str,
    actor: Optional[str],
    home: Optional[str],
) -> None:
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        ws.transition(target, who, note=note)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("incident", Text(ws.incident_id, style=C_ACCENT))
    table.add_row("status", _status(ws.state["status"]))
    table.add_row("actor", who)
    if note:
        table.add_row("note", note)
    console.print(Panel(table, title="[bold]LIFECYCLE UPDATED[/]",
                        border_style=STATUS_STYLE.get(ws.state["status"], "cyan"),
                        box=box.ROUNDED))


@lifecycle_app.command("contain")
def lifecycle_contain(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    note: str = typer.Option("", "--note", "-n", help="Containment note."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Mark the incident CONTAINED and audit the transition."""
    _transition("CONTAINED", incident_id, note, actor, home)


@lifecycle_app.command("eradicate")
def lifecycle_eradicate(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    note: str = typer.Option("", "--note", "-n", help="Eradication note."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Mark the incident ERADICATING and audit the transition."""
    _transition("ERADICATING", incident_id, note, actor, home)


@lifecycle_app.command("recover")
def lifecycle_recover(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    note: str = typer.Option("", "--note", "-n", help="Recovery note."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Mark the incident RECOVERING and audit the transition."""
    _transition("RECOVERING", incident_id, note, actor, home)


@lifecycle_app.command("resolve")
def lifecycle_resolve(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    note: str = typer.Option("", "--note", "-n", help="Resolution note."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Mark the incident RESOLVED once integrity gates are green."""
    _transition("RESOLVED", incident_id, note, actor, home)


@lifecycle_app.command("seal")
def lifecycle_seal(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Seal a closed incident after all integrity gates verify green."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        ws.seal_incident(who)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("incident", Text(ws.incident_id, style=C_ACCENT))
    table.add_row("status", _status(ws.state["status"]))
    table.add_row("actor", who)
    console.print(Panel(table, title="[bold]INCIDENT SEALED[/]",
                        border_style=STATUS_STYLE["SEALED"], box=box.ROUNDED))


# ---- registry --------------------------------------------------------------- #

@registry_app.command("init")
def registry_init(
    home: Optional[str] = typer.Option(None, "--home"),
    registry: Optional[str] = typer.Option(None, "--registry", help="Registry JSON path."),
    seal: Optional[str] = typer.Option(None, "--seal", help="Registry seal JSON path."),
    root_key: Optional[str] = typer.Option(None, "--root-key", help="Root signing key path."),
    root_verify: Optional[str] = typer.Option(None, "--root-verify", help="Root verify key JSON path."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    sequence: int = typer.Option(1, "--sequence", help="Initial signed registry sequence."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing registry/root key set."),
):
    """Create a root-signed trusted signer registry."""
    h = _home(home)
    registry_path = _registry_path(h, registry)
    seal_path = _registry_seal_path(registry_path, seal)
    root_key_path = _root_key_path(h, root_key)
    root_verify_path = _root_verify_path(h, root_verify)
    targets = (registry_path, seal_path, root_key_path, root_verify_path)
    if not force:
        existing = [str(p) for p in targets if p.exists()]
        if existing:
            console.print(f"[{C_BAD}]✗ refusing to overwrite existing file(s): {', '.join(existing)}[/]")
            raise typer.Exit(code=1)
    if sequence < 0:
        console.print(f"[{C_BAD}]✗ sequence must be non-negative[/]")
        raise typer.Exit(code=1)

    root_sk, root_vk = signing.generate_signing_keypair()
    reg = TrustedSignerRegistry()
    if sequence > 0:
        reg.bump(sequence)

    registry_path.parent.mkdir(parents=True, exist_ok=True)
    save_registry(reg, registry_path)
    write_seal(
        seal_registry(reg, root_sk, signer=actor or default_actor(), sealed_when=_now()),
        seal_path,
    )
    _write_root_key(root_key_path, root_sk)
    _write_root_verify(root_verify_path, root_vk)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("registry", Text(str(registry_path), style=C_ACCENT))
    table.add_row("seal", str(seal_path))
    table.add_row("root key", str(root_key_path))
    table.add_row("root verify", str(root_verify_path))
    table.add_row("sequence", str(reg.sequence))
    table.add_row("root fingerprint", signing.key_fingerprint(root_vk))
    console.print(Panel(table, title="[bold]REGISTRY INITIALIZED[/]",
                        border_style="green", box=box.ROUNDED))


@registry_app.command("trust-active")
def registry_trust_active(
    home: Optional[str] = typer.Option(None, "--home"),
    registry: Optional[str] = typer.Option(None, "--registry", help="Registry JSON path."),
    seal: Optional[str] = typer.Option(None, "--seal", help="Registry seal JSON path."),
    root_key: Optional[str] = typer.Option(None, "--root-key", help="Root signing key path."),
    actor: Optional[str] = typer.Option(None, "--actor", help="Signer identity to store."),
    incident_id: Optional[str] = typer.Option(None, "--id", help="Incident signer to trust (default: active)."),
    sequence: Optional[int] = typer.Option(None, "--sequence", help="Next registry sequence."),
):
    """Add the active incident signer to the trusted registry and reseal it."""
    h = _home(home)
    registry_path = _registry_path(h, registry)
    seal_path = _registry_seal_path(registry_path, seal)
    root_key_path = _root_key_path(h, root_key)

    try:
        root_sk = _read_root_key(root_key_path)
        reg = load_signed_registry(registry_path, seal_path, root_sk.verify_key)
        ws = IncidentWorkspace.load(h, incident_id) if incident_id else IncidentWorkspace.load_current(h)
        _, signer_info = ws._read_verify_key()
        next_sequence = sequence if sequence is not None else reg.sequence + 1
        reg.add_signer(
            actor or ws.state.get("actor") or default_actor(),
            signer_info["verify_key"],
            created_when=_now(),
        )
        reg.bump(next_sequence)
        save_registry(reg, registry_path)
        write_seal(
            seal_registry(reg, root_sk, signer=actor or default_actor(), sealed_when=_now()),
            seal_path,
        )
    except (WorkspaceError, RegistryError, OSError, ValueError, KeyError) as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("registry", Text(str(registry_path), style=C_ACCENT))
    table.add_row("incident", ws.incident_id)
    table.add_row("trusted signer", actor or ws.state.get("actor") or default_actor())
    table.add_row("fingerprint", signer_info["fingerprint"])
    table.add_row("sequence", str(reg.sequence))
    console.print(Panel(table, title="[bold]SIGNER TRUSTED[/]",
                        border_style="green", box=box.ROUNDED))


@registry_app.command("verify")
def registry_verify(
    home: Optional[str] = typer.Option(None, "--home"),
    registry: Optional[str] = typer.Option(None, "--registry", help="Registry JSON path."),
    seal: Optional[str] = typer.Option(None, "--seal", help="Registry seal JSON path."),
    root_verify: Optional[str] = typer.Option(None, "--root-verify", help="Root verify key JSON path."),
    min_sequence: int = typer.Option(0, "--min-sequence", help="Anti-rollback sequence floor."),
):
    """Verify the trusted signer registry's root seal."""
    h = _home(home)
    registry_path = _registry_path(h, registry)
    seal_path = _registry_seal_path(registry_path, seal)
    root_verify_path = _root_verify_path(h, root_verify)
    try:
        reg = load_registry(registry_path)
        registry_seal = load_seal(seal_path)
        root_vk, root_info = _read_root_verify(root_verify_path)
        ok, reason = verify_registry_seal(
            reg, registry_seal, root_vk, min_sequence=min_sequence
        )
    except (RegistryError, OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        console.print(f"[{C_BAD}]✗ registry verification failed: {e}[/]")
        raise typer.Exit(code=1)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("registry", Text(str(registry_path), style=C_ACCENT))
    table.add_row("sequence", str(reg.sequence))
    table.add_row("signers", str(len(reg.entries)))
    table.add_row("root fingerprint", root_info["fingerprint"])
    table.add_row("reason", reason)
    if ok:
        console.print(Panel(table, title="[bold]REGISTRY VERIFIED[/]",
                            border_style="green", box=box.ROUNDED))
        console.print(f"[{C_OK}]✓ registry root seal verified[/]")
        return
    console.print(Panel(table, title="[bold]REGISTRY VERIFICATION FAILED[/]",
                        border_style="red", box=box.ROUNDED))
    raise typer.Exit(code=1)


# ---- doctor / use / close ---------------------------------------------------- #

@app.command()
def doctor(home: Optional[str] = typer.Option(None, "--home")):
    """Check local Coreline workspace health and integrity."""
    h = _home(home)
    ids = IncidentWorkspace.list_incidents(h)
    cur = IncidentWorkspace.current_id(h)

    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("home", Text(str(h), style=C_ACCENT))
    table.add_row("incidents", str(len(ids)))
    table.add_row("active", cur or "none")

    problems = []
    active_ws = None
    if cur:
        try:
            active_ws = IncidentWorkspace.load(h, cur)
        except WorkspaceError as e:
            problems.append(str(e))
    elif ids:
        problems.append("no active incident selected")

    if active_ws:
        v = active_ws.verify()
        table.add_row("active status", _status(active_ws.state.get("status", "")))
        table.add_row("manifest signature", "valid" if v["manifest_signature"] else "invalid")
        table.add_row("custody chain", "intact" if v["custody_chain"] else "broken")
        table.add_row("audit chain", "intact" if v["audit_chain"] else "broken")
        table.add_row("storage artifacts", "verified" if v["storage_artifacts"] else "failed")
        if not v["manifest_signature"]:
            problems.append("active manifest signature invalid")
        if not v["custody_chain"]:
            problems.append("active custody chain broken")
        if not v["audit_chain"]:
            problems.append(f"active audit chain broken at seq {v['audit_bad_seq']}")
        if not v["storage_artifacts"]:
            problems.append("active stored evidence artifacts failed verification")

    border = "green" if not problems else "yellow"
    console.print(Panel(table, title="[bold]CORELINE DOCTOR[/]", border_style=border,
                        box=box.ROUNDED))
    if problems:
        for p in problems:
            console.print(f"[{C_WARN}]! {p}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ workspace ready[/]")


@app.command()
def verify(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    all_incidents: bool = typer.Option(False, "--all", help="Verify every incident in the store."),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Verify manifests, custody, audit chain, and stored local evidence artifacts."""
    h = _home(home)
    workspaces = []
    try:
        if all_incidents:
            ids = IncidentWorkspace.list_incidents(h)
            workspaces = [IncidentWorkspace.load(h, iid) for iid in ids]
        else:
            workspaces = [IncidentWorkspace.load(h, incident_id)
                          if incident_id else IncidentWorkspace.load_current(h)]
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)

    if not workspaces:
        console.print(f"[{C_DIM}]no incidents under {h}[/]")
        return

    failed = []
    for ws in workspaces:
        v = ws.verify()
        ok = _verification_ok(v)
        if not ok:
            failed.append(ws.incident_id)
        console.print(_verification_panel(ws, v, ok))

    if failed:
        console.print(f"[{C_BAD}]✗ verification failed for {', '.join(failed)}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ verification passed for {len(workspaces)} incident(s)[/]")


def _verification_ok(v: dict) -> bool:
    return all(
        bool(v[key])
        for key in ("manifest_signature", "custody_chain", "audit_chain", "storage_artifacts")
    )


def _verification_panel(ws: IncidentWorkspace, v: dict, ok: bool) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=C_DIM, justify="right")
    table.add_column()
    table.add_row("incident", Text(ws.incident_id, style=C_ACCENT))
    table.add_row("title", ws.state.get("title", ""))
    table.add_row("status", _status(ws.state.get("status", "")))
    table.add_row("manifest", "valid" if v["manifest_signature"] else "invalid")
    table.add_row("custody", "intact" if v["custody_chain"] else f"broken @ {v['custody_bad_index']}")
    table.add_row("audit", "intact" if v["audit_chain"] else f"broken @ seq {v['audit_bad_seq']}")
    table.add_row("storage", "verified" if v["storage_artifacts"] else "failed")
    table.add_row("manifest hash", Text(str(v.get("manifest_hash") or ""), style=C_DIM))
    if v["storage_missing"]:
        table.add_row("missing", ", ".join(v["storage_missing"]))
    if v["storage_bad_hash"]:
        table.add_row("bad hash", "; ".join(v["storage_bad_hash"]))
    if v["storage_unverifiable"]:
        table.add_row("unverifiable", "; ".join(v["storage_unverifiable"]))
    border = "green" if ok else "red"
    return Panel(table, title="[bold]VERIFICATION[/]", border_style=border, box=box.ROUNDED)


@app.command("use")
def use_incident(
    incident_id: str = typer.Argument(..., help="Incident ID to make active."),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Make an existing incident the active incident."""
    try:
        ws = IncidentWorkspace.load(_home(home), incident_id)
        ws.make_active()
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    console.print(f"[{C_OK}]✓ active incident set to {ws.incident_id}[/]")


@app.command()
def close(
    incident_id: Optional[str] = typer.Option(None, "--id", help="Target incident (default: active)."),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
    raw: bool = typer.Option(False, "--raw", help="Print raw markdown instead of rendered."),
    force: bool = typer.Option(False, "--force", help="Close even when pre-closure gates fail."),
    reason: Optional[str] = typer.Option(None, "--reason", help="Required reason when using --force."),
):
    """Generate the final PIR and close the incident."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        md = ws.close_incident(who, force=force, reason=reason)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)

    if raw:
        console.print(md)
    else:
        console.print(Panel(Markdown(md), title="[bold]INCIDENT CLOSED[/]",
                            border_style="green", box=box.ROUNDED))
    console.print(f"[{C_DIM}]final PIR written to {ws.report_path}[/]")


# ---- timeline show ----------------------------------------------------------- #

@timeline_app.command("show")
def timeline_show(
    incident_id: Optional[str] = typer.Option(None, "--id"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Render the incident's hash-linked audit log as a chronological timeline."""
    ws = _load(home, incident_id)
    entries = ws.audit_entries()

    table = Table(
        title=f"[bold]TIMELINE[/]  {ws.incident_id}  ·  {ws.state['title']}",
        box=box.SIMPLE_HEAVY, header_style=C_ACCENT,
        title_style="white", border_style="cyan", pad_edge=False,
    )
    table.add_column("#", justify="right", style=C_DIM, no_wrap=True)
    table.add_column("timestamp (UTC)", style="white", no_wrap=True)
    table.add_column("actor", style="magenta", overflow="fold")
    table.add_column("action", style=C_OK, no_wrap=True)
    table.add_column("detail", style="white", overflow="fold", ratio=1, min_width=20)
    table.add_column("hash", style=C_DIM, no_wrap=True)

    for e in entries:
        detail_bits = []
        for k in ("severity", "title", "file", "sha256", "note", "manifest_hash"):
            if k in e.detail and e.detail[k] not in (None, ""):
                val = str(e.detail[k])
                if k in ("sha256", "manifest_hash"):
                    val = val[:12] + "…"
                detail_bits.append(f"{k}={val}")
        ts = e.timestamp.replace("T", " ")[:19]  # trim microseconds for density
        table.add_row(str(e.seq), ts, e.actor, e.action,
                      "  ".join(detail_bits), e.entry_hash()[:10] + "…")

    console.print(table)
    ok, bad = _verify_and_note(ws)
    if ok:
        console.print(f"[{C_OK}]✓ audit chain verified — {len(entries)} events, "
                      f"tamper-evident[/]")
    else:
        console.print(f"[{C_BAD}]✗ audit chain BROKEN at seq {bad}[/]")


def _verify_and_note(ws: IncidentWorkspace):
    v = ws.verify()
    return v["audit_chain"], v["audit_bad_seq"]


# ---- status ------------------------------------------------------------------ #

@app.command()
def status(
    incident_id: Optional[str] = typer.Option(None, "--id"),
    home: Optional[str] = typer.Option(None, "--home"),
):
    """Show lifecycle state, quality gates, evidence count, and integrity."""
    ws = _load(home, incident_id)
    S = ws.state
    gates = ws.gates()

    head = Table.grid(padding=(0, 3))
    head.add_column(style=C_DIM, justify="right")
    head.add_column()
    head.add_row("incident", Text(ws.incident_id, style=C_ACCENT))
    head.add_row("title", S["title"])
    head.add_row("severity", _sev(S["severity"]))
    head.add_row("status", _status(S["status"]))
    head.add_row("evidence", f"{S.get('evidence_count', 0)} item(s)")
    head.add_row("declared", S["created_at"])
    head.add_row("updated", S["updated_at"])

    gate_tbl = Table(box=box.MINIMAL, header_style=C_ACCENT, expand=True,
                     border_style=C_DIM)
    gate_tbl.add_column("", no_wrap=True)
    gate_tbl.add_column("quality gate")
    gate_tbl.add_column("detail", style=C_DIM)
    n_pass = 0
    for g in gates:
        if g.passed:
            n_pass += 1
            mark = Text("✓", style=C_OK)
        else:
            mark = Text("✗", style=C_BAD)
        gate_tbl.add_row(mark, g.label, g.detail)

    gate_style = C_OK if n_pass == len(gates) else (C_WARN if n_pass else C_BAD)
    console.print(Panel(head, title="[bold]INCIDENT STATUS[/]",
                        border_style=STATUS_STYLE.get(S["status"], "cyan"),
                        box=box.ROUNDED))
    console.print(Panel(gate_tbl,
                        title=f"[bold]QUALITY GATES[/]  [{gate_style}]{n_pass}/{len(gates)} passing[/]",
                        border_style="cyan", box=box.ROUNDED))


# ---- report ------------------------------------------------------------------ #

@app.command()
def report(
    incident_id: Optional[str] = typer.Option(None, "--id"),
    actor: Optional[str] = typer.Option(None, "--actor"),
    home: Optional[str] = typer.Option(None, "--home"),
    raw: bool = typer.Option(False, "--raw", help="Print raw markdown instead of rendered."),
):
    """Generate and display the Post-Incident Report (PIR)."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        md = ws.generate_report(who)
    except WorkspaceError as e:
        console.print(f"[{C_BAD}]✗ {e}[/]")
        raise typer.Exit(code=1)
    if raw:
        console.print(md)
    else:
        console.print(Panel(Markdown(md), title="[bold]POST-INCIDENT REPORT[/]",
                            border_style="green", box=box.ROUNDED))
    console.print(f"[{C_DIM}]written to {ws.report_path}[/]")


# ---- list (bonus, keeps demos navigable) ------------------------------------- #

@app.command("list")
def list_incidents(home: Optional[str] = typer.Option(None, "--home")):
    """List all incidents in the store."""
    h = _home(home)
    ids = IncidentWorkspace.list_incidents(h)
    cur = IncidentWorkspace.current_id(h)
    if not ids:
        console.print(f"[{C_DIM}]no incidents under {h}[/]")
        return
    table = Table(box=box.SIMPLE, header_style=C_ACCENT)
    table.add_column("active", justify="center")
    table.add_column("incident id", style=C_ACCENT)
    table.add_column("severity")
    table.add_column("status")
    table.add_column("title")
    for iid in ids:
        try:
            ws = IncidentWorkspace.load(h, iid)
        except WorkspaceError:
            continue
        table.add_row("●" if iid == cur else "", iid, ws.state.get("severity", ""),
                      ws.state.get("status", ""), ws.state.get("title", ""))
    console.print(table)


def main() -> None:  # console-script entrypoint
    app()


if __name__ == "__main__":
    app()
