"""
Coreline — self-hosted web console (Streamlit).

A visual, zero-CLI front-end over the deterministic ``core`` (via
``core.incident.IncidentWorkspace``). Everything is buttons, forms, a
drag-and-drop evidence dropzone, a color-coded timeline, and green/red integrity badges.

Run via ``./run_gui.sh`` (which calls ``streamlit run interfaces/gui/app.py``).
"""
from __future__ import annotations

from html import escape
import tempfile
from pathlib import Path

import streamlit as st

from core.incident import (
    IncidentWorkspace,
    WorkspaceError,
    SEVERITIES,
    default_actor,
)

# --------------------------------------------------------------------------- #
# palette + page chrome
# --------------------------------------------------------------------------- #
BG = "#0d1117"; PANEL = "#161b22"; INK = "#e6edf3"; DIM = "#8b949e"
ACCENT = "#22d3ee"; OK = "#3fb950"; BAD = "#f85149"; WARN = "#d29922"
SEV_COLOR = {"SEV1": "#f85149", "SEV2": "#db6d28", "SEV3": "#d29922",
             "SEV4": "#58a6ff", "SEV5": "#8b949e"}
STATUS_COLOR = {
    "OPEN": WARN,
    "DECLARED": WARN,
    "INVESTIGATING": ACCENT,
    "CONTAINED": "#58a6ff",
    "ERADICATING": "#d2a8ff",
    "RECOVERING": "#f0f6fc",
    "RESOLVED": OK,
    "CLOSED": DIM,
    "SEALED": DIM,
}
ACTION_COLOR = {"incident-declared": "#58a6ff", "evidence-added": OK,
                "observation-created": "#d2a8ff", "observation-corrected": WARN,
                "observation-retracted": BAD, "report-generated": "#bc8cff"}

st.set_page_config(page_title="Coreline — Incident Console", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

st.markdown(f"""
<style>
  .stApp {{ background:{BG}; color:{INK}; }}
  section[data-testid="stSidebar"] {{ background:{PANEL}; }}
  .coreline-title {{ font-size:1.9rem; font-weight:800; letter-spacing:.18em;
                 color:{ACCENT}; margin:0; }}
  .coreline-sub {{ color:{DIM}; font-size:.8rem; letter-spacing:.1em; margin-top:-4px; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:6px;
            font-weight:700; font-size:.8rem; letter-spacing:.04em; }}
  .gate {{ display:flex; align-items:center; gap:10px; padding:10px 14px;
           background:{PANEL}; border-radius:10px; margin-bottom:8px;
           border-left:5px solid {DIM}; }}
  .gate .dot {{ height:14px; width:14px; border-radius:50%; box-shadow:0 0 8px; }}
  .gate .lbl {{ font-weight:600; }}
  .gate .det {{ color:{DIM}; font-size:.8rem; margin-left:auto; }}
  .evt {{ padding:8px 14px; background:{PANEL}; border-radius:8px; margin-bottom:6px;
          border-left:4px solid {DIM}; font-family:ui-monospace,monospace;
          font-size:.82rem; }}
  .evt .t {{ color:{DIM}; }} .evt .a {{ color:{INK}; font-weight:700; }}
  .mono {{ font-family:ui-monospace,monospace; color:{DIM}; font-size:.78rem;
           word-break:break-all; }}
</style>
""", unsafe_allow_html=True)


def badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}22;color:{color};border:1px solid {color}55;">{text}</span>'


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #
HOME = IncidentWorkspace.resolve_home()
HOME.mkdir(parents=True, exist_ok=True)
ACTOR = default_actor()


def current_ws():
    iid = st.session_state.get("incident_id") or IncidentWorkspace.current_id(HOME)
    if not iid:
        return None
    try:
        ws = IncidentWorkspace.load(HOME, iid)
        st.session_state["incident_id"] = iid
        return ws
    except WorkspaceError:
        st.session_state.pop("incident_id", None)
        return None


# --------------------------------------------------------------------------- #
# sidebar — incident selection + declare
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.markdown('<p class="coreline-title">◈ Coreline</p>'
                '<p class="coreline-sub">INCIDENT RESPONSE CONSOLE</p>', unsafe_allow_html=True)
    st.markdown("---")

    st.markdown("#### 🚨 Declare incident")
    with st.form("declare", clear_on_submit=True):
        title = st.text_input("Title", placeholder="DB Exfiltration Alert")
        severity = st.selectbox("Severity", SEVERITIES, index=0)
        if st.form_submit_button("Declare incident ➜", use_container_width=True,
                                 type="primary"):
            if not title.strip():
                st.error("Title is required.")
            else:
                ws = IncidentWorkspace.declare(HOME, title=title, severity=severity,
                                               actor=ACTOR)
                st.session_state["incident_id"] = ws.incident_id
                st.success(f"Declared {ws.incident_id}")
                st.rerun()

    st.markdown("---")
    st.markdown("#### 📁 Incidents")
    ids = IncidentWorkspace.list_incidents(HOME)
    if ids:
        cur = st.session_state.get("incident_id") or IncidentWorkspace.current_id(HOME)
        sel = st.radio("Select incident", ids,
                       index=ids.index(cur) if cur in ids else 0,
                       label_visibility="collapsed")
        if sel and sel != st.session_state.get("incident_id"):
            st.session_state["incident_id"] = sel
            IncidentWorkspace.load(HOME, sel).make_active()
            st.rerun()
    else:
        st.caption("No incidents yet — declare one above.")

    # ---- audit controls (demo) --------------------------------------------- #
    _active = st.session_state.get("incident_id") or IncidentWorkspace.current_id(HOME)
    if _active:
        with st.expander("⚠️ Audit controls (demo)", expanded=False):
            st.caption("For live demos: break the sealed audit chain and watch the "
                       "integrity gates react, then repair it to reset.")
            try:
                _aws = IncidentWorkspace.load(HOME, _active)
            except WorkspaceError:
                _aws = None
            if _aws is not None:
                if st.button("⚠️ Simulate Evidence Tampering",
                             use_container_width=True, key="tamper"):
                    if _aws.simulate_tamper():
                        st.rerun()
                if st.button("🔄 Reset / Repair Audit Log",
                             use_container_width=True, key="repair"):
                    _aws.repair_audit()
                    st.rerun()

    st.caption(f"store · `{HOME}`")
    st.caption(f"analyst · `{ACTOR}`")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
ws = current_ws()

if ws is None:
    st.markdown('<p class="coreline-title" style="font-size:2.4rem;">◈ Coreline</p>',
                unsafe_allow_html=True)
    st.markdown("### Declare an incident from the sidebar to begin.")
    st.info("Coreline hashes (SHA-256), Ed25519-signs, and tamper-proofs every piece of "
            "evidence — no command line required.")
    st.stop()

S = ws.state
gates = {g.key: g for g in ws.gates()}
v = ws.verify()

# ---- header ---------------------------------------------------------------- #
h1, h2, h3, h4 = st.columns([4, 1.4, 1.6, 1.6])
with h1:
    st.markdown(f"### {S['title']}")
    st.markdown(f'<span class="mono">{ws.incident_id}</span>', unsafe_allow_html=True)
with h2:
    st.markdown("**Severity**")
    st.markdown(badge(S["severity"], SEV_COLOR.get(S["severity"], DIM)),
                unsafe_allow_html=True)
with h3:
    st.markdown("**Status**")
    st.markdown(badge(S["status"], STATUS_COLOR.get(S["status"], DIM)),
                unsafe_allow_html=True)
with h4:
    st.markdown("**Evidence**")
    st.markdown(f"### {S.get('evidence_count', 0)}")

st.markdown("---")

left, right = st.columns([1.6, 1])

# ---- left: evidence dropzone + timeline ------------------------------------ #
with left:
    st.markdown("#### 📥 Evidence dropzone")
    locked = ws.is_closed or S.get("status") == "RESOLVED"
    if locked:
        st.markdown(badge("🔒 EVIDENCE INTAKE LOCKED", DIM),
                    unsafe_allow_html=True)
    else:
        st.caption("Drag & drop logs / pcaps — each file is SHA-256 hashed, copied to "
                   "write-only storage, and the manifest is Ed25519-sealed automatically.")
    note = st.text_input("Analyst note (applied to dropped files)",
                         placeholder="SIEM alert: outbound to TOR exit", key="note",
                         disabled=locked)
    uploads = st.file_uploader("Drop evidence files here",
                               accept_multiple_files=True,
                               label_visibility="collapsed",
                               key=f"up-{ws.incident_id}",
                               disabled=locked)
    if uploads and not locked:
        existing = ws.evidence_shas()
        added = 0
        for uf in uploads:
            data = uf.getvalue()
            from core.evidence.hashing import sha256_bytes
            if sha256_bytes(data) in existing:
                continue  # idempotent: already sealed (survives Streamlit reruns)
            tmpdir = Path(tempfile.mkdtemp())
            tmp = tmpdir / uf.name
            tmp.write_bytes(data)
            try:
                res = ws.add_evidence(str(tmp), st.session_state.get("note", ""), ACTOR)
                existing.add(res["sha256"])
                added += 1
            except WorkspaceError as e:
                st.error(f"{uf.name}: {e}")
        if added:
            st.success(f"Sealed {added} new evidence item(s).")
            st.rerun()

    items = ws.evidence_items()
    if items:
        st.markdown("##### Sealed evidence")
        for it in items:
            st.markdown(
                f'<div class="evt" style="border-left-color:{OK};">'
                f'<span class="a">{Path(it.path).name}</span> '
                f'<span class="t">· {it.size} bytes · {it.collected_at[:19].replace("T"," ")}</span><br>'
                f'<span class="mono">sha256 {it.sha256}</span></div>',
                unsafe_allow_html=True)

    st.markdown("#### 🔎 Observations")
    evidence_options = [it.sha256 for it in items]
    with st.form("observation", clear_on_submit=True):
        obs_text = st.text_area("Observation text", height=90,
                                placeholder="CloudTrail shows database access from unusual source IP",
                                disabled=ws.is_closed)
        obs_evidence = st.multiselect("Evidence references", evidence_options,
                                      format_func=lambda h: h[:16] + "…",
                                      disabled=ws.is_closed)
        obs_disposition = st.selectbox(
            "Disposition",
            ("OBSERVED", "SUSPECTED", "REFUTED", "INCONCLUSIVE"),
            disabled=ws.is_closed,
        )
        obs_subject = st.text_input("Subject", placeholder="prod-db, user@example.com, host-01",
                                    disabled=ws.is_closed)
        if st.form_submit_button("Record observation", use_container_width=True,
                                 disabled=ws.is_closed):
            try:
                ws.add_observation(
                    text=obs_text,
                    actor=ACTOR,
                    evidence_refs=list(obs_evidence),
                    disposition=obs_disposition,
                    subject=obs_subject,
                )
                st.rerun()
            except WorkspaceError as e:
                st.error(str(e))

    for obs in ws.observations():
        ev = ", ".join(h[:12] for h in obs.evidence) or "no evidence"
        subject = f" · {escape(obs.subject)}" if obs.subject else ""
        state = "RETRACTED" if ws.observation_is_retracted(obs.observation_id) else obs.disposition
        st.markdown(
            f'<div class="evt" style="border-left-color:#d2a8ff;">'
            f'<span class="a">{obs.observation_id}</span> '
            f'<span class="t">· {state}{subject} · evidence {ev}</span><br>'
            f'{escape(obs.text)}</div>',
            unsafe_allow_html=True)
        for amendment in ws.observation_amendments(obs.observation_id):
            st.markdown(
                f'<div class="evt" style="border-left-color:{WARN};margin-left:18px;">'
                f'<span class="a">{amendment.amendment_type}</span> '
                f'<span class="t">· {amendment.amendment_id} · '
                f'{amendment.created_at[:19].replace("T"," ")}</span><br>'
                f'{escape(amendment.text)}</div>',
                unsafe_allow_html=True)

    st.markdown("#### 🕓 Visual timeline")
    ok_audit = v["audit_chain"]
    st.markdown(
        badge("● AUDIT CHAIN VERIFIED" if ok_audit else
              f"● AUDIT CHAIN BROKEN @ seq {v['audit_bad_seq']}",
              OK if ok_audit else BAD), unsafe_allow_html=True)
    for e in ws.audit_entries():
        color = ACTION_COLOR.get(e.action, DIM)
        detail = " · ".join(
            f"{k}={str(val)[:24]}" for k, val in e.detail.items()
            if k in ("severity", "title", "file", "note", "sha256") and val)
        st.markdown(
            f'<div class="evt" style="border-left-color:{color};">'
            f'<span class="t">#{e.seq} · {e.timestamp[:19].replace("T"," ")}Z · {e.actor}</span> '
            f'{badge(e.action, color)}<br>'
            f'<span class="t">{detail}</span> '
            f'<span class="mono">↳ {e.entry_hash()[:12]}…</span></div>',
            unsafe_allow_html=True)

# ---- right: quality-gate badges + report ----------------------------------- #
with right:
    st.markdown("#### 🛡️ Integrity gates")
    n_pass = sum(1 for g in gates.values() if g.passed)
    for g in gates.values():
        col = OK if g.passed else BAD
        st.markdown(
            f'<div class="gate" style="border-left-color:{col};">'
            f'<span class="dot" style="background:{col};color:{col};"></span>'
            f'<span class="lbl">{g.label}</span>'
            f'<span class="det">{g.detail[:34]}</span></div>',
            unsafe_allow_html=True)
    tone = OK if n_pass == len(gates) else (WARN if n_pass else BAD)
    st.markdown(badge(f"{n_pass}/{len(gates)} GATES PASSING", tone),
                unsafe_allow_html=True)

    st.markdown("#### ⏱️ Lifecycle")
    lifecycle_steps = [
        ("CONTAINED", "Contain"),
        ("ERADICATING", "Eradicate"),
        ("RECOVERING", "Recover"),
        ("RESOLVED", "Resolve"),
    ]
    cols = st.columns(2)
    for idx, (target, label) in enumerate(lifecycle_steps):
        with cols[idx % 2]:
            if st.button(label, use_container_width=True, disabled=ws.is_closed,
                         key=f"life-{target}"):
                try:
                    ws.transition(target, ACTOR, note=f"GUI lifecycle: {label}")
                    st.rerun()
                except WorkspaceError as e:
                    st.error(str(e))

    st.markdown("#### 🔒 Closure")
    if ws.is_sealed:
        st.markdown(badge("● INCIDENT SEALED", STATUS_COLOR["SEALED"]),
                    unsafe_allow_html=True)
        st.caption("Final archive sealed. Incident is read-only.")
    elif ws.is_closed:
        st.markdown(badge("● INCIDENT CLOSED", STATUS_COLOR["CLOSED"]),
                    unsafe_allow_html=True)
        st.caption("Lifecycle locked; final signed PIR generated. Evidence intake "
                   "is disabled.")
        if st.button("Seal incident", use_container_width=True, key="seal"):
            try:
                ws.seal_incident(ACTOR)
                st.rerun()
            except WorkspaceError as e:
                st.error(str(e))
    else:
        if st.button("🔒 Close incident (seal final PIR + lock intake)",
                     use_container_width=True, key="close"):
            try:
                ws.close_incident(ACTOR)
                st.rerun()
            except WorkspaceError as e:
                st.error(str(e))

    st.markdown("#### 📄 Post-incident report")
    if st.button("Generate PIR ➜", use_container_width=True, type="primary",
                 disabled=ws.is_closed):
        try:
            ws.generate_report(ACTOR)
            st.rerun()
        except WorkspaceError as e:
            st.error(str(e))
    if ws.report_path.exists():
        md = ws.report_path.read_text(encoding="utf-8")
        with st.expander("View PIR", expanded=False):
            st.markdown(md)
        st.download_button("⬇ Download report.md", md,
                           file_name=f"{ws.incident_id}-PIR.md",
                           use_container_width=True)
