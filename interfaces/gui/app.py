"""Coreline investigation workstation.

Streamlit front-end over the deterministic Coreline domain layer. The GUI is an
operator interface only: incident state, evidence integrity, observations,
lifecycle, audit, and reporting remain owned by ``core.incident``.
"""
from __future__ import annotations

from html import escape
import tempfile
from pathlib import Path
from typing import Iterable

import streamlit as st

from core.incident import (
    CLAIM_STATUSES,
    IncidentWorkspace,
    WorkspaceError,
    SEVERITIES,
    default_actor,
)
from core.evidence.hashing import sha256_bytes


BG = "#0b0f14"
SURFACE = "#111820"
SURFACE_2 = "#16212b"
LINE = "#263341"
INK = "#e7edf3"
MUTED = "#91a0ad"
ACCENT = "#2dd4bf"
OK = "#38bdf8"
GOOD = "#22c55e"
BAD = "#ef4444"
WARN = "#f59e0b"

SEV_COLOR = {
    "SEV1": "#ef4444",
    "SEV2": "#f97316",
    "SEV3": "#f59e0b",
    "SEV4": "#38bdf8",
    "SEV5": "#94a3b8",
}
STATUS_COLOR = {
    "OPEN": WARN,
    "DECLARED": WARN,
    "INVESTIGATING": ACCENT,
    "CONTAINED": "#60a5fa",
    "ERADICATING": "#c084fc",
    "RECOVERING": "#e2e8f0",
    "RESOLVED": GOOD,
    "CLOSED": MUTED,
    "SEALED": MUTED,
}
ACTION_COLOR = {
    "incident-declared": "#60a5fa",
    "incident-metadata-updated": ACCENT,
    "evidence-added": GOOD,
    "observation-created": "#c084fc",
    "observation-corrected": WARN,
    "observation-retracted": BAD,
    "claim-created": "#2dd4bf",
    "claim-corrected": WARN,
    "claim-status-updated": OK,
    "claim-withdrawn": BAD,
    "lifecycle-transition": OK,
    "report-generated": "#a78bfa",
    "incident-closed": MUTED,
    "incident-sealed": MUTED,
}

st.set_page_config(
    page_title="Coreline - Investigation Workstation",
    page_icon="CL",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    f"""
<style>
  .stApp {{ background:{BG}; color:{INK}; }}
  section[data-testid="stSidebar"] {{ background:{SURFACE}; border-right:1px solid {LINE}; }}
  div[data-testid="stVerticalBlock"] {{ gap: .75rem; }}
  .cl-brand {{ font-size:1.35rem; font-weight:800; letter-spacing:.16em; color:{ACCENT}; margin:0; }}
  .cl-sub {{ color:{MUTED}; font-size:.74rem; letter-spacing:.08em; margin-top:-6px; }}
  .cl-header {{ border-bottom:1px solid {LINE}; padding-bottom:14px; margin-bottom:14px; }}
  .cl-title {{ font-size:1.35rem; font-weight:760; margin:0 0 2px 0; color:{INK}; }}
  .cl-id {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; color:{MUTED}; font-size:.82rem; }}
  .chip {{ display:inline-block; padding:3px 9px; border-radius:5px; font-weight:720; font-size:.76rem; }}
  .band {{ border-top:1px solid {LINE}; padding-top:12px; margin-top:8px; }}
  .row {{ background:{SURFACE}; border-left:3px solid {LINE}; padding:9px 12px; margin-bottom:6px; }}
  .row strong {{ color:{INK}; }}
  .muted {{ color:{MUTED}; }}
  .mono {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; color:{MUTED}; font-size:.78rem; word-break:break-all; }}
  .trust-ok {{ color:{GOOD}; font-weight:760; }}
  .trust-bad {{ color:{BAD}; font-weight:760; }}
  .gate {{ display:flex; gap:10px; align-items:flex-start; border-bottom:1px solid {LINE}; padding:8px 0; }}
  .gate .name {{ font-weight:680; }}
  .gate .detail {{ color:{MUTED}; font-size:.78rem; margin-left:auto; text-align:right; }}
  .section-title {{ color:{INK}; font-size:1rem; font-weight:760; margin:4px 0 8px 0; }}
</style>
""",
    unsafe_allow_html=True,
)


def chip(text: str, color: str) -> str:
    return (
        f'<span class="chip" style="background:{color}1f;color:{color};'
        f'border:1px solid {color}66;">{escape(text)}</span>'
    )


def row_html(title: str, body: str, color: str = LINE, meta: str = "") -> str:
    meta_html = f'<div class="muted">{escape(meta)}</div>' if meta else ""
    return (
        f'<div class="row" style="border-left-color:{color};">'
        f"<strong>{escape(title)}</strong>{meta_html}<div>{body}</div></div>"
    )


def gate_trust(gates) -> tuple[bool, str]:
    trust_keys = {"custody", "signature", "audit", "storage", "observations", "claims"}
    relevant = [g for g in gates if g.key in trust_keys]
    ok = all(g.passed for g in relevant)
    return ok, "Integrity verified" if ok else "Integrity issue detected"


def short_hash(value: str, size: int = 12) -> str:
    return value[:size] + ("..." if len(value) > size else "")


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


def render_sidebar() -> str:
    st.sidebar.markdown('<p class="cl-brand">CORELINE</p><p class="cl-sub">IR WORKSTATION</p>',
                        unsafe_allow_html=True)
    st.sidebar.markdown("---")

    with st.sidebar.expander("Declare incident", expanded=False):
        with st.form("declare", clear_on_submit=True):
            title = st.text_input("Title", placeholder="Production database compromise")
            severity = st.selectbox("Severity", SEVERITIES, index=0)
            if st.form_submit_button("Declare", use_container_width=True, type="primary"):
                if not title.strip():
                    st.error("Title is required.")
                else:
                    ws = IncidentWorkspace.declare(HOME, title=title, severity=severity, actor=ACTOR)
                    st.session_state["incident_id"] = ws.incident_id
                    st.success(f"Declared {ws.incident_id}")
                    st.rerun()

    ids = IncidentWorkspace.list_incidents(HOME)
    if ids:
        cur = st.session_state.get("incident_id") or IncidentWorkspace.current_id(HOME)
        sel = st.sidebar.radio(
            "Incident",
            ids,
            index=ids.index(cur) if cur in ids else 0,
        )
        if sel and sel != st.session_state.get("incident_id"):
            st.session_state["incident_id"] = sel
            IncidentWorkspace.load(HOME, sel).make_active()
            st.rerun()
    else:
        st.sidebar.caption("No incidents yet.")

    st.sidebar.markdown("---")
    nav = st.sidebar.radio(
        "Workspace",
        ("Overview", "Evidence", "Observations", "Claims", "Timeline", "Reports"),
        key="workspace_nav",
    )
    st.sidebar.markdown("---")
    st.sidebar.caption(f"store `{HOME}`")
    st.sidebar.caption(f"analyst `{ACTOR}`")
    return nav


def render_header(ws: IncidentWorkspace, gates) -> None:
    state = ws.state
    trust_ok, trust_text = gate_trust(gates)
    cols = st.columns([4.2, 1, 1.3, 1.3, 1.3])
    with cols[0]:
        st.markdown(
            f'<div class="cl-header"><p class="cl-title">{escape(state["title"])}</p>'
            f'<span class="cl-id">{ws.incident_id}</span></div>',
            unsafe_allow_html=True,
        )
    with cols[1]:
        st.caption("Severity")
        st.markdown(chip(state["severity"], SEV_COLOR.get(state["severity"], MUTED)),
                    unsafe_allow_html=True)
    with cols[2]:
        st.caption("Lifecycle")
        st.markdown(chip(state["status"], STATUS_COLOR.get(state["status"], MUTED)),
                    unsafe_allow_html=True)
    with cols[3]:
        st.caption("Record trust")
        klass = "trust-ok" if trust_ok else "trust-bad"
        st.markdown(f'<span class="{klass}">{trust_text}</span>', unsafe_allow_html=True)
    with cols[4]:
        st.caption("Security")
        if st.button("Security & Integrity", use_container_width=True):
            st.session_state["security_panel"] = not st.session_state.get("security_panel", False)


def render_security_panel(ws: IncidentWorkspace, gates, verify_result) -> None:
    st.markdown('<div class="section-title">Security & Integrity</div>', unsafe_allow_html=True)
    trust_ok, trust_text = gate_trust(gates)
    st.markdown(
        f'<span class="{"trust-ok" if trust_ok else "trust-bad"}">{trust_text}</span>',
        unsafe_allow_html=True,
    )
    st.caption("Detailed verification remains visible on demand; cryptographic complexity stays out of the main workflow.")
    st.markdown('<div class="band"></div>', unsafe_allow_html=True)
    for gate in gates:
        mark = "PASS" if gate.passed else "FAIL"
        color = GOOD if gate.passed else BAD
        st.markdown(
            f'<div class="gate"><span>{chip(mark, color)}</span>'
            f'<span class="name">{escape(gate.label)}</span>'
            f'<span class="detail">{escape(gate.detail)}</span></div>',
            unsafe_allow_html=True,
        )
    st.markdown('<div class="band"></div>', unsafe_allow_html=True)
    st.caption(f"manifest `{verify_result.get('manifest_hash') or 'not available'}`")
    st.caption(f"signer `{verify_result.get('fingerprint') or 'not available'}`")
    st.caption(f"audit chain `{verify_result.get('audit_chain')}`")

    with st.expander("Demo audit controls", expanded=False):
        st.caption("Break and repair the audit chain for local demos.")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Simulate Evidence Tampering", use_container_width=True):
                if ws.simulate_tamper():
                    st.rerun()
        with c2:
            if st.button("Reset / Repair Audit Log", use_container_width=True):
                ws.repair_audit()
                st.rerun()


def recent_activity(ws: IncidentWorkspace, limit: int = 8) -> Iterable:
    return list(ws.audit_entries())[-limit:][::-1]


def render_overview(ws: IncidentWorkspace) -> None:
    state = ws.state
    st.markdown('<div class="section-title">Incident Overview</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Evidence", state.get("evidence_count", 0))
    c2.metric("Observations", state.get("observation_count", 0))
    c3.metric("Claims", state.get("claim_count", 0))
    c4.metric("Updated", str(state.get("updated_at", ""))[:10])

    st.markdown('<div class="band"></div>', unsafe_allow_html=True)
    left, right = st.columns([1.25, 1])
    with left:
        st.markdown("#### Mutable incident metadata")
        with st.form("metadata"):
            title = st.text_input("Title", value=state.get("title", ""), disabled=ws.is_closed)
            severity = st.selectbox(
                "Severity",
                SEVERITIES,
                index=SEVERITIES.index(state.get("severity", "SEV3"))
                if state.get("severity") in SEVERITIES else 2,
                disabled=ws.is_closed,
            )
            description = st.text_area(
                "Investigation summary",
                value=state.get("description", ""),
                height=120,
                disabled=ws.is_closed,
            )
            submitted = st.form_submit_button("Save metadata", disabled=ws.is_closed)
            if submitted:
                try:
                    ws.update_metadata(ACTOR, title=title, severity=severity, description=description)
                    st.success("Incident metadata updated.")
                    st.rerun()
                except WorkspaceError as exc:
                    st.error(str(exc))
        if ws.is_closed:
            st.caption("Closed and sealed incident states lock mutable metadata.")

    with right:
        st.markdown("#### Lifecycle")
        steps = [
            ("CONTAINED", "Contain"),
            ("ERADICATING", "Eradicate"),
            ("RECOVERING", "Recover"),
            ("RESOLVED", "Resolve"),
        ]
        cols = st.columns(2)
        for idx, (target, label) in enumerate(steps):
            with cols[idx % 2]:
                if st.button(label, use_container_width=True, disabled=ws.is_closed, key=f"life-{target}"):
                    try:
                        ws.transition(target, ACTOR, note=f"GUI lifecycle: {label}")
                        st.rerun()
                    except WorkspaceError as exc:
                        st.error(str(exc))

        st.markdown("#### Recent activity")
        for entry in recent_activity(ws, 6):
            color = ACTION_COLOR.get(entry.action, LINE)
            meta = f"#{entry.seq} · {entry.timestamp[:19].replace('T', ' ')}Z · {entry.actor}"
            detail = ", ".join(
                f"{k}={str(v)[:32]}" for k, v in entry.detail.items()
                if k in ("severity", "title", "file", "note", "sha256", "observation_id", "claim_id", "amendment_id")
            )
            st.markdown(row_html(entry.action, escape(detail), color=color, meta=meta),
                        unsafe_allow_html=True)


def render_evidence(ws: IncidentWorkspace) -> None:
    state = ws.state
    st.markdown('<div class="section-title">Evidence</div>', unsafe_allow_html=True)
    locked = ws.is_closed or state.get("status") == "RESOLVED"
    if locked:
        st.warning("Evidence intake is locked for this lifecycle state.")
    else:
        with st.form("evidence_upload", clear_on_submit=True):
            note = st.text_input("Custody note", placeholder="CloudTrail export from prod account")
            uploads = st.file_uploader("Add evidence files", accept_multiple_files=True)
            if st.form_submit_button("Seal evidence", type="primary"):
                if not uploads:
                    st.error("Choose at least one evidence file.")
                else:
                    existing = ws.evidence_shas()
                    added = 0
                    for upload in uploads:
                        data = upload.getvalue()
                        if sha256_bytes(data) in existing:
                            continue
                        tmpdir = Path(tempfile.mkdtemp())
                        tmp = tmpdir / upload.name
                        tmp.write_bytes(data)
                        try:
                            res = ws.add_evidence(str(tmp), note, ACTOR)
                            existing.add(res["sha256"])
                            added += 1
                        except WorkspaceError as exc:
                            st.error(f"{upload.name}: {exc}")
                    if added:
                        st.success(f"Sealed {added} evidence item(s).")
                        st.rerun()

    items = ws.evidence_items()
    if not items:
        st.info("No evidence recorded yet.")
        return
    observation_links = {}
    for obs in ws.observations():
        for sha in obs.evidence:
            observation_links.setdefault(sha, []).append(obs.observation_id)
    rows = []
    for item in items:
        rows.append({
            "file": Path(item.path).name,
            "size": item.size,
            "sha256": item.sha256,
            "collected": item.collected_at,
            "observations": ", ".join(observation_links.get(item.sha256, [])) or "-",
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)


def render_observations(ws: IncidentWorkspace) -> None:
    st.markdown('<div class="section-title">Observations</div>', unsafe_allow_html=True)
    items = ws.evidence_items()
    evidence_options = [item.sha256 for item in items]
    with st.form("observation", clear_on_submit=True):
        text = st.text_area(
            "What was observed?",
            height=110,
            placeholder="CloudTrail shows database access from unusual source IP",
            disabled=ws.is_closed,
        )
        c1, c2 = st.columns([1, 1])
        evidence = c1.multiselect(
            "Supporting evidence",
            evidence_options,
            format_func=lambda h: short_hash(h, 16),
            disabled=ws.is_closed,
        )
        disposition = c2.selectbox(
            "Disposition",
            ("OBSERVED", "SUSPECTED", "REFUTED", "INCONCLUSIVE"),
            disabled=ws.is_closed,
        )
        subject = st.text_input("Subject/system", placeholder="prod-db, user@example.com, host-01", disabled=ws.is_closed)
        if st.form_submit_button("Record observation", type="primary", disabled=ws.is_closed):
            try:
                ws.add_observation(text=text, actor=ACTOR, evidence_refs=list(evidence),
                                   disposition=disposition, subject=subject)
                st.rerun()
            except WorkspaceError as exc:
                st.error(str(exc))

    observations = ws.observations()
    if not observations:
        st.info("No observations recorded yet.")
        return

    st.markdown('<div class="band"></div>', unsafe_allow_html=True)
    for obs in observations:
        effective = ws.effective_observation(obs.observation_id)
        color = BAD if effective.current_status == "RETRACTED" else "#c084fc"
        subject = f" · {obs.subject}" if obs.subject else ""
        meta = (
            f"{effective.current_status}{subject} · created {obs.created_at[:19].replace('T', ' ')}Z "
            f"by {obs.creator}"
        )
        evidence = ", ".join(short_hash(h, 12) for h in obs.evidence) or "no evidence"
        st.markdown(
            row_html(
                obs.observation_id,
                f"{escape(effective.current_text)}<br><span class=\"mono\">evidence {escape(evidence)}</span>",
                color=color,
                meta=meta,
            ),
            unsafe_allow_html=True,
        )
        with st.expander(f"Amend {obs.observation_id}", expanded=False):
            if obs.text != effective.current_text:
                st.caption(f"Original: {obs.text}")
            for amendment in effective.amendments:
                st.caption(
                    f"{amendment.amendment_type} {amendment.amendment_id} "
                    f"{amendment.created_at[:19].replace('T', ' ')}Z: {amendment.text}"
                )
            c1, c2 = st.columns(2)
            with c1:
                with st.form(f"correct-{obs.observation_id}"):
                    correction = st.text_area("Correction", height=90, disabled=ws.is_closed or bool(effective.retraction))
                    reason = st.text_input("Reason", disabled=ws.is_closed or bool(effective.retraction))
                    if st.form_submit_button("Save correction", disabled=ws.is_closed or bool(effective.retraction)):
                        try:
                            ws.correct_observation(obs.observation_id, correction, ACTOR, reason=reason)
                            st.rerun()
                        except WorkspaceError as exc:
                            st.error(str(exc))
            with c2:
                with st.form(f"retract-{obs.observation_id}"):
                    reason = st.text_area("Retraction reason", height=90, disabled=ws.is_closed or bool(effective.retraction))
                    if st.form_submit_button("Retract observation", disabled=ws.is_closed or bool(effective.retraction)):
                        try:
                            ws.retract_observation(obs.observation_id, reason, ACTOR)
                            st.rerun()
                        except WorkspaceError as exc:
                            st.error(str(exc))


def render_claims(ws: IncidentWorkspace) -> None:
    st.markdown('<div class="section-title">Claims</div>', unsafe_allow_html=True)
    effective_observations = [
        ws.effective_observation(obs.observation_id)
        for obs in ws.observations()
    ]
    active_observations = [
        effective for effective in effective_observations
        if not effective.retraction
    ]
    observation_options = [effective.observation.observation_id for effective in active_observations]
    observation_text = {
        effective.observation.observation_id: effective.current_text
        for effective in active_observations
    }
    if not active_observations:
        st.info("Record a non-retracted observation before adding a claim.")
    with st.form("claim", clear_on_submit=True):
        text = st.text_area(
            "What claim is supported by the investigation record?",
            height=110,
            placeholder="Production database was accessed from an unusual source IP",
            disabled=ws.is_closed or not active_observations,
        )
        c1, c2 = st.columns([1, 1])
        observations = c1.multiselect(
            "Supporting observations",
            observation_options,
            format_func=lambda oid: f"{oid} - {observation_text.get(oid, '')[:70]}",
            disabled=ws.is_closed or not active_observations,
        )
        status = c2.selectbox("Status", CLAIM_STATUSES, disabled=ws.is_closed or not active_observations)
        subject = st.text_input("Subject/system", placeholder="prod-db, user@example.com, host-01",
                                disabled=ws.is_closed or not active_observations)
        if st.form_submit_button("Record claim", type="primary", disabled=ws.is_closed or not active_observations):
            try:
                ws.add_claim(
                    text=text,
                    actor=ACTOR,
                    observation_refs=list(observations),
                    status=status,
                    subject=subject,
                )
                st.rerun()
            except WorkspaceError as exc:
                st.error(str(exc))

    claims = ws.claims()
    if not claims:
        st.info("No claims recorded yet.")
        return

    st.markdown('<div class="band"></div>', unsafe_allow_html=True)
    for claim in claims:
        effective = ws.effective_claim(claim.claim_id)
        subject = f" · {claim.subject}" if claim.subject else ""
        meta = (
            f"{effective.current_status}{subject} · created {claim.created_at[:19].replace('T', ' ')}Z "
            f"by {claim.creator}"
        )
        refs = ", ".join(claim.observations)
        st.markdown(
            row_html(
                claim.claim_id,
                f"{escape(effective.current_text)}<br><span class=\"mono\">observations {escape(refs)}</span>",
                color=BAD if effective.current_status == "WITHDRAWN" else ACCENT,
                meta=meta,
            ),
            unsafe_allow_html=True,
        )
        with st.expander(f"Supporting observations for {claim.claim_id}", expanded=False):
            if claim.text != effective.current_text:
                st.caption(f"Original claim: {claim.text}")
            for amendment in effective.amendments:
                status = f" -> {amendment.status}" if amendment.status else ""
                st.caption(
                    f"{amendment.amendment_type}{status} {amendment.amendment_id} "
                    f"{amendment.created_at[:19].replace('T', ' ')}Z: {amendment.text}"
                )
            for observation_id in claim.observations:
                try:
                    effective_observation = ws.effective_observation(observation_id)
                except WorkspaceError as exc:
                    st.error(str(exc))
                    continue
                st.caption(f"{observation_id}: {effective_observation.current_status}")
                st.write(effective_observation.current_text)
            c1, c2, c3 = st.columns(3)
            with c1:
                with st.form(f"claim-correct-{claim.claim_id}"):
                    correction = st.text_area(
                        "Correction",
                        height=90,
                        disabled=ws.is_closed or bool(effective.withdrawal),
                    )
                    reason = st.text_input("Reason", disabled=ws.is_closed or bool(effective.withdrawal))
                    if st.form_submit_button("Save claim correction",
                                             disabled=ws.is_closed or bool(effective.withdrawal)):
                        try:
                            ws.correct_claim(claim.claim_id, correction, ACTOR, reason=reason)
                            st.rerun()
                        except WorkspaceError as exc:
                            st.error(str(exc))
            with c2:
                with st.form(f"claim-status-{claim.claim_id}"):
                    status = st.selectbox(
                        "Status update",
                        CLAIM_STATUSES,
                        disabled=ws.is_closed or bool(effective.withdrawal),
                    )
                    reason = st.text_area("Reason", height=90,
                                          disabled=ws.is_closed or bool(effective.withdrawal))
                    if st.form_submit_button("Save status",
                                             disabled=ws.is_closed or bool(effective.withdrawal)):
                        try:
                            ws.update_claim_status(claim.claim_id, status, ACTOR, reason)
                            st.rerun()
                        except WorkspaceError as exc:
                            st.error(str(exc))
            with c3:
                with st.form(f"claim-withdraw-{claim.claim_id}"):
                    reason = st.text_area("Withdrawal reason", height=90,
                                          disabled=ws.is_closed or bool(effective.withdrawal))
                    if st.form_submit_button("Withdraw claim",
                                             disabled=ws.is_closed or bool(effective.withdrawal)):
                        try:
                            ws.withdraw_claim(claim.claim_id, reason, ACTOR)
                            st.rerun()
                        except WorkspaceError as exc:
                            st.error(str(exc))


def render_timeline(ws: IncidentWorkspace, verify_result) -> None:
    st.markdown('<div class="section-title">Timeline</div>', unsafe_allow_html=True)
    if verify_result["audit_chain"]:
        st.markdown('<span class="trust-ok">AUDIT CHAIN VERIFIED</span>', unsafe_allow_html=True)
    else:
        st.markdown(f'<span class="trust-bad">AUDIT CHAIN BROKEN @ seq {verify_result["audit_bad_seq"]}</span>',
                    unsafe_allow_html=True)
    for entry in ws.audit_entries():
        color = ACTION_COLOR.get(entry.action, LINE)
        meta = f"#{entry.seq} · {entry.timestamp[:19].replace('T', ' ')}Z · {entry.actor}"
        detail = ", ".join(
            f"{k}={str(v)[:48]}" for k, v in entry.detail.items()
            if k in ("severity", "title", "file", "note", "sha256", "observation_id", "amendment_id", "claim_id", "status")
            and v not in (None, "")
        )
        hash_text = f'<span class="mono">hash {entry.entry_hash()[:12]}...</span>'
        st.markdown(row_html(entry.action, f"{escape(detail)}<br>{hash_text}", color=color, meta=meta),
                    unsafe_allow_html=True)


def render_reports(ws: IncidentWorkspace) -> None:
    st.markdown('<div class="section-title">Reports</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Generate PIR", type="primary", use_container_width=True, disabled=ws.is_closed):
            try:
                ws.generate_report(ACTOR)
                st.rerun()
            except WorkspaceError as exc:
                st.error(str(exc))
    with c2:
        if st.button("Close incident", use_container_width=True, disabled=ws.is_closed):
            try:
                ws.close_incident(ACTOR)
                st.rerun()
            except WorkspaceError as exc:
                st.error(str(exc))
    with c3:
        if st.button("Seal incident", use_container_width=True, disabled=not ws.is_closed or ws.is_sealed):
            try:
                ws.seal_incident(ACTOR)
                st.rerun()
            except WorkspaceError as exc:
                st.error(str(exc))
    if ws.is_sealed:
        st.info("Incident is sealed and read-only.")
    elif ws.is_closed:
        st.info("Incident is closed. It can still be sealed after verification.")

    if ws.report_path.exists():
        md = ws.report_path.read_text(encoding="utf-8")
        with st.expander("View PIR", expanded=True):
            st.markdown(md)
        st.download_button("Download report.md", md, file_name=f"{ws.incident_id}-PIR.md")
    else:
        st.info("No PIR generated yet.")


HOME = IncidentWorkspace.resolve_home()
HOME.mkdir(parents=True, exist_ok=True)
ACTOR = default_actor()

nav = render_sidebar()
ws = current_ws()

if ws is None:
    st.markdown('<p class="cl-brand" style="font-size:2rem;">CORELINE</p>', unsafe_allow_html=True)
    st.markdown("### Declare an incident to begin an investigation.")
    st.info("Coreline preserves evidence, observations, audit history, and incident lifecycle through the deterministic core.")
    st.stop()

gates_list = ws.gates()
verify_result = ws.verify()
render_header(ws, gates_list)

if st.session_state.get("security_panel", False):
    main_col, security_col = st.columns([2.15, 1])
else:
    main_col = st.container()
    security_col = None

with main_col:
    if nav == "Overview":
        render_overview(ws)
    elif nav == "Evidence":
        render_evidence(ws)
    elif nav == "Observations":
        render_observations(ws)
    elif nav == "Claims":
        render_claims(ws)
    elif nav == "Timeline":
        render_timeline(ws, verify_result)
    elif nav == "Reports":
        render_reports(ws)

if security_col is not None:
    with security_col:
        render_security_panel(ws, gates_list, verify_result)
