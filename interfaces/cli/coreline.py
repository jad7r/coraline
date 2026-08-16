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

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
from rich import box

from core.incident import (
    IncidentWorkspace,
    WorkspaceError,
    SEVERITIES,
    default_actor,
)

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
    "DECLARED": "bold yellow",
    "INVESTIGATING": "bold cyan",
    "CONTAINED": "bold blue",
    "RESOLVED": "bold green",
    "CLOSED": "grey58",
}

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Coreline — deterministic incident-response console.",
    rich_markup_mode="rich",
)
evidence_app = typer.Typer(no_args_is_help=True, help="Evidence collection & integrity.")
timeline_app = typer.Typer(no_args_is_help=True, help="Incident timeline.")
app.add_typer(evidence_app, name="evidence")
app.add_typer(timeline_app, name="timeline")


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
):
    """Generate the final PIR and close the incident."""
    ws = _load(home, incident_id)
    who = actor or default_actor()
    try:
        md = ws.close_incident(who)
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
    md = ws.generate_report(who)
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
