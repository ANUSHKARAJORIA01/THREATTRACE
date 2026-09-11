"""
app.py
------
THREATTRACE — AI-Powered Threat Detection & Forensic Intelligence
Platform. Streamlit entry point.

This file controls navigation/UI only; all analysis logic lives in the
`modules/` package and persistence lives in `database/database.py`.

FRONTEND REDESIGN NOTE: This restyles the UI into a dark navy/cyan SOC
dashboard with a persistent sidebar and a granular page set (Dashboard /
Analyze Evidence / AI Risk Analysis / IOC Intelligence / Network
Intelligence / Investigation Graph / Forensic Timeline / Evidence /
Reports). It does NOT change any backend logic — every number, badge,
table, and chart below is built directly from the existing modules'
real return values (risk_engine.recalculate_case_risk, correlation_engine,
next_steps, forensic_engine, protection_scan, threat_intelligence,
etc.). Anything the current backend does not compute (IOC reputation,
ASN, WHOIS, malware family, per-indicator confidence, file hashes) is
shown as an honest empty/not-available state rather than invented.

PROTOTYPE DISCLAIMER: This application is an educational/research
prototype. Risk scores and classifications are heuristic/ML estimates,
not definitive security or identity determinations.
"""

import os
import sys
import math
from datetime import datetime, timedelta

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import database as db
from modules import (
    email_detector, network_detector, document_detector,
    identity_detector, geolocation, threat_intelligence,
    forensic_engine, risk_engine, protection_scan
)
from utils import timeline as timeline_utils
from utils import report_generator

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="THREATTRACE — AI Forensic Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# CENTRALIZED THEME / CSS
# ---------------------------------------------------------------------------

ACCENT = "#22d3ee"
ACCENT_DIM = "#0e7490"
BG_MAIN = "#090d13"
BG_CARD = "#111827"
BG_CARD_ALT = "#0d1420"
BORDER = "#1f2937"
RED = "#ef4444"
AMBER = "#f59e0b"
GREEN = "#22c55e"

THEME_CSS = f"""
<style>
.stApp {{
    background: radial-gradient(1200px 600px at 10% -10%, #0d2230 0%, {BG_MAIN} 45%);
}}
section[data-testid="stSidebar"] {{
    background-color: #060910;
    border-right: 1px solid {BORDER};
}}
section[data-testid="stSidebar"] * {{ color: #cbd5e1; }}
h1, h2, h3 {{ color: #e5e7eb !important; }}

div[data-testid="stMetric"] {{
    background: linear-gradient(180deg, {BG_CARD} 0%, {BG_CARD_ALT} 100%);
    border: 1px solid {BORDER};
    border-radius: 12px;
    padding: 14px 16px;
    box-shadow: 0 0 0 1px rgba(34,211,238,0.04), 0 4px 18px rgba(0,0,0,0.35);
}}
div[data-testid="stMetric"] label {{ color: #94a3b8 !important; }}

.section-header {{
    font-size: 1.02rem;
    font-weight: 700;
    color: #e5e7eb;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    border-left: 3px solid {ACCENT};
    padding-left: 10px;
    margin: 18px 0 10px 0;
}}

.tt-card {{
    background: linear-gradient(180deg, {BG_CARD} 0%, {BG_CARD_ALT} 100%);
    border: 1px solid {BORDER};
    border-radius: 12px;
    padding: 16px 18px;
    margin-bottom: 12px;
    box-shadow: 0 0 0 1px rgba(34,211,238,0.03), 0 4px 14px rgba(0,0,0,0.30);
}}
.tt-card-title {{ font-weight: 700; color: #e5e7eb; font-size: 0.95rem; margin-bottom: 4px; }}
.tt-card-sub {{ color: #94a3b8; font-size: 0.82rem; }}

.tt-select-card {{
    background: linear-gradient(180deg, {BG_CARD} 0%, {BG_CARD_ALT} 100%);
    border: 1px solid {BORDER};
    border-radius: 14px;
    padding: 22px 16px;
    text-align: center;
    transition: border-color 0.15s ease;
}}
.tt-select-card.active {{ border: 1px solid {ACCENT}; box-shadow: 0 0 0 1px rgba(34,211,238,0.25); }}
.tt-select-icon {{ font-size: 1.6rem; }}

.badge {{
    display: inline-block;
    padding: 3px 12px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.72rem;
    letter-spacing: 0.03em;
    text-transform: uppercase;
}}
.badge-LOW, .badge-SAFE, .badge-CLEAN {{ background-color: rgba(34,197,94,0.15); color: {GREEN}; border: 1px solid rgba(34,197,94,0.3); }}
.badge-MEDIUM, .badge-SUSPICIOUS {{ background-color: rgba(245,158,11,0.15); color: {AMBER}; border: 1px solid rgba(245,158,11,0.3); }}
.badge-HIGH, .badge-DANGEROUS, .badge-MALICIOUS {{ background-color: rgba(239,68,68,0.15); color: {RED}; border: 1px solid rgba(239,68,68,0.35); }}
.badge-CRITICAL {{ background-color: rgba(239,68,68,0.28); color: #fecaca; border: 1px solid rgba(239,68,68,0.5); }}
.badge-UNKNOWN, .badge-NONE, .badge-OPEN {{ background-color: rgba(148,163,184,0.15); color: #cbd5e1; border: 1px solid rgba(203,213,225,0.3); }}
.badge-ACCENT {{ background-color: rgba(34,211,238,0.14); color: {ACCENT}; border: 1px solid rgba(34,211,238,0.35); }}

.disclaimer-box {{
    background-color: #0f1620;
    border-left: 4px solid {ACCENT_DIM};
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 0.85rem;
    color: #94a3b8;
    margin-bottom: 14px;
}}

.empty-state {{
    text-align: center;
    padding: 30px 18px;
    color: #64748b;
    border: 1px dashed {BORDER};
    border-radius: 12px;
    background: {BG_CARD_ALT};
}}
.empty-state-title {{ font-weight: 700; color: #94a3b8; letter-spacing: 0.03em; margin-bottom: 4px; }}

.tl-item {{
    display: flex; gap: 12px; padding: 10px 0;
    border-left: 2px solid {BORDER};
    margin-left: 6px; padding-left: 18px; position: relative;
}}
.tl-dot {{
    position: absolute; left: -7px; top: 14px;
    width: 12px; height: 12px; border-radius: 50%;
    border: 2px solid {BG_MAIN};
}}
.tl-time {{ color: #64748b; font-size: 0.78rem; }}
.tl-event {{ color: #e5e7eb; font-size: 0.9rem; }}

.topbar-right {{ color: #94a3b8; font-size: 0.85rem; }}
.status-dot {{
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    margin-right: 6px;
}}
.status-on {{ background-color: {GREEN}; box-shadow: 0 0 6px {GREEN}; }}
.status-off {{ background-color: {RED}; box-shadow: 0 0 6px {RED}; }}
.status-line {{ font-size: 0.78rem; color: #94a3b8; margin: 3px 0; }}

/* ---- Sidebar navigation (Change 1: reference-screenshot nav styling) ---- */
.tt-nav-brand {{ display: flex; align-items: center; gap: 10px; padding: 4px 2px 14px 2px; }}
.tt-nav-brand-icon {{
    width: 38px; height: 38px; border-radius: 10px;
    background: linear-gradient(135deg, {ACCENT}, {ACCENT_DIM});
    display: flex; align-items: center; justify-content: center;
    font-size: 1.15rem; box-shadow: 0 0 14px rgba(34,211,238,0.35);
}}
.tt-nav-brand-title {{ font-weight: 800; color: #f1f5f9; font-size: 1.05rem; line-height: 1.1; }}
.tt-nav-brand-sub {{ color: #64748b; font-size: 0.72rem; line-height: 1.2; }}

section[data-testid="stSidebar"] div[role="radiogroup"] {{
    gap: 4px; display: flex; flex-direction: column;
}}
section[data-testid="stSidebar"] div[role="radiogroup"] label {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 10px;
    padding: 9px 12px;
    margin: 0;
    transition: background 0.15s ease, border-color 0.15s ease;
}}
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {{
    background: rgba(148,163,184,0.07);
}}
section[data-testid="stSidebar"] div[role="radiogroup"] label div[data-testid="stMarkdownContainer"] p {{
    font-size: 0.94rem; color: #cbd5e1; font-weight: 500;
}}
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {{
    background: rgba(34,211,238,0.10);
    border: 1px solid rgba(34,211,238,0.35);
}}
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) div[data-testid="stMarkdownContainer"] p {{
    color: {ACCENT}; font-weight: 700;
}}
</style>
"""
st.markdown(THEME_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# REUSABLE UI HELPER COMPONENTS
# ---------------------------------------------------------------------------

def badge(label, text=None):
    if label is None:
        label = "UNKNOWN"
    key = str(label).upper().replace(" ", "_")
    known = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "SAFE", "SUSPICIOUS", "DANGEROUS",
             "CLEAN", "MALICIOUS", "UNKNOWN", "NONE", "OPEN"]
    css_key = key if key in known else "UNKNOWN"
    display = text if text is not None else label
    return f'<span class="badge badge-{css_key}">{display}</span>'


def risk_badge(level):
    return badge(level or "LOW")


def disclaimer(text):
    st.markdown(f'<div class="disclaimer-box">⚠️ {text}</div>', unsafe_allow_html=True)


def page_header(title, subtitle=None):
    st.markdown(f"## {title}")
    if subtitle:
        st.caption(subtitle)


def section_header(text):
    st.markdown(f'<div class="section-header">{text}</div>', unsafe_allow_html=True)


def card(title, body_html="", sub=None):
    sub_html = f'<div class="tt-card-sub">{sub}</div>' if sub else ""
    st.markdown(
        f'<div class="tt-card"><div class="tt-card-title">{title}</div>{sub_html}{body_html}</div>',
        unsafe_allow_html=True
    )


def empty_state(title, message="", icon="ℹ️"):
    st.markdown(
        f'<div class="empty-state">{icon}<br><div class="empty-state-title">{title}</div>{message}</div>',
        unsafe_allow_html=True
    )


def render_timeline(events):
    """Vertical forensic timeline: TIME / SOURCE (category) / EVENT — the
    three real fields utils.timeline.build_timeline actually produces.
    There is no separate structured 'evidence' field beyond the event
    text itself, so it is not fabricated as a fourth column."""
    if not events:
        empty_state("NO TIMELINE EVENTS AVAILABLE",
                     "Analyze or add evidence to this case to populate the timeline.", "🕒")
        return
    dot_colors = {"Email": RED, "Network": AMBER, "Document": ACCENT,
                  "Geolocation": "#a78bfa", "Threat Intelligence": RED,
                  "Correlation": GREEN}
    for e in events:
        color = dot_colors.get(e.get("category"), "#94a3b8")
        st.markdown(
            f'<div class="tl-item"><div class="tl-dot" style="background:{color}"></div>'
            f'<div><div class="tl-time">{e.get("time")} &nbsp;•&nbsp; SOURCE: {e.get("category")}</div>'
            f'<div class="tl-event">{e.get("event")}</div></div></div>',
            unsafe_allow_html=True
        )


REL_TYPE_COLORS = {
    "has_evidence": "#64748b",
    "sent_by": "#fb923c",
    "contains_indicator": "#facc15",
    "matches_threat_intelligence": RED,
    "resolves_to_location": "#60a5fa",
    "screened_for_identity_consistency": "#c084fc",
}


def render_relationship_graph(graph):
    """
    Dependency-free node/edge diagram built with plotly (no networkx or
    graphviz required). Nodes are placed on a circle; edges are grouped
    into one plotly trace PER relationship type (from the real,
    backend-provided relationship_edges) so each relationship type gets
    its own legend entry and consistent color — nothing here is
    fabricated, every edge/label comes straight from forensic_engine.
    Falls back to the untyped `edges` list (still real data) if
    relationship_edges isn't present, for backward compatibility.
    """
    nodes = graph.get("nodes", [])
    if not nodes:
        empty_state("NO RELATIONSHIP DATA AVAILABLE",
                     "Not enough evidence yet to build an evidence graph.", "🕸️")
        return

    node_type_colors = {
        "Investigation": ACCENT, "Email": RED, "Sender": "#fb923c",
        "Indicator": "#facc15", "Document": "#a78bfa", "Identity check": "#c084fc",
        "Network": GREEN, "Geolocation": "#60a5fa", "TI Match": RED,
    }

    def node_color(name):
        for prefix, color in node_type_colors.items():
            if name.startswith(prefix):
                return color
        return "#94a3b8"

    n = len(nodes)
    radius = 1.0
    positions = {
        name: (radius * math.cos(2 * math.pi * i / n), radius * math.sin(2 * math.pi * i / n))
        for i, name in enumerate(nodes)
    }

    fig = go.Figure()

    rel_edges = graph.get("relationship_edges")
    if rel_edges:
        by_type = {}
        for r in rel_edges:
            by_type.setdefault(r["relationship"], []).append((r["source"], r["target"]))
        for rel_type, pairs in by_type.items():
            ex, ey = [], []
            for src, tgt in pairs:
                if src in positions and tgt in positions:
                    x0, y0 = positions[src]
                    x1, y1 = positions[tgt]
                    ex += [x0, x1, None]
                    ey += [y0, y1, None]
            fig.add_trace(go.Scatter(
                x=ex, y=ey, mode="lines",
                line=dict(width=1.6, color=REL_TYPE_COLORS.get(rel_type, "#334155")),
                name=rel_type.replace("_", " "), hoverinfo="none"
            ))
    else:
        edges = graph.get("edges", [])
        ex, ey = [], []
        for src, tgt in edges:
            if src in positions and tgt in positions:
                x0, y0 = positions[src]
                x1, y1 = positions[tgt]
                ex += [x0, x1, None]
                ey += [y0, y1, None]
        fig.add_trace(go.Scatter(x=ex, y=ey, mode="lines",
                                  line=dict(width=1, color="#334155"),
                                  name="relationship", hoverinfo="none"))

    node_x = [positions[n_][0] for n_ in nodes]
    node_y = [positions[n_][1] for n_ in nodes]
    node_colors = [node_color(n_) for n_ in nodes]
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y, mode="markers+text", text=nodes,
        textposition="top center", textfont=dict(size=9, color="#cbd5e1"),
        marker=dict(size=16, color=node_colors, line=dict(width=1, color=BG_MAIN)),
        hovertext=nodes, hoverinfo="text", name="evidence node", showlegend=False
    ))
    fig.update_layout(
        showlegend=True, legend=dict(orientation="h", y=-0.08, font=dict(color="#cbd5e1", size=10)),
        height=540, plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False), yaxis=dict(visible=False),
        margin=dict(l=10, r=10, t=10, b=10),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_correlation_panel(correlation):
    """RELATED ACTIVITY — real correlation_engine output only."""
    if not correlation or not correlation.get("related"):
        st.info("No related activity detected.")
        return
    st.markdown(
        f"{badge('ACCENT', correlation.get('label'))} "
        f"&nbsp; Correlation Confidence: {badge(correlation.get('confidence'))}",
        unsafe_allow_html=True
    )
    st.caption(correlation.get("explanation", ""))
    if correlation.get("shared_indicators"):
        st.write("**Shared Indicators:**")
        rows = [{
            "Indicator Type": m.get("indicator_type"),
            "Indicator": m.get("indicator_value"),
            "Related Investigation": f"INV-{m.get('other_investigation_id'):04d} — {m.get('other_case_name')}",
        } for m in correlation["shared_indicators"]]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    if correlation.get("related_investigation_ids"):
        ids_str = ", ".join(f"INV-{i:04d}" for i in correlation["related_investigation_ids"])
        st.caption(f"Related Investigation IDs: {ids_str}")
    st.caption("Exact, literal indicator overlap only — a lead for the investigator, not a "
               "confirmed link, and it does not factor into the overall risk score.")


def render_next_steps_panel(next_step_list):
    if not next_step_list:
        empty_state("NO NEXT STEPS AVAILABLE", "No evidence-based next steps identified yet.", "✅")
        return
    for item in next_step_list:
        card(item.get("step", ""), sub=f"Why: {item.get('reason', '')}")


TI_EVIDENCE_SEVERITY = {"LOW": 25, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 95}


# ---------------------------------------------------------------------------
# CHANGE 3 helpers — Network Intelligence / Geolocation must be gated on
# whether the ACTIVE investigation's own evidence actually justifies them.
# These are new, pure app.py/UI-layer helpers: they only read already-stored
# evidence via the existing db/forensic_engine functions and never call the
# geolocation module speculatively or invent a result. No backend module is
# modified.
# ---------------------------------------------------------------------------

import re as _re
_IPV4_RE = _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _case_has_network_evidence(investigation_id):
    """True only if real network-flow/log evidence has already been recorded
    for this case (a CSV/demo upload was actually analyzed and saved) —
    never true just because the case exists or has other evidence types."""
    try:
        return bool(db.get_network_analysis(investigation_id))
    except Exception:
        return False


def _find_usable_ip_in_case(investigation_id):
    """
    Look for a real IP address already present in THIS case's own stored
    evidence — never invents or guesses one. Checked in order:
      1. An existing network-flow record's destination/source IP.
      2. An existing geolocation record already saved for this case.
      3. A literal IPv4-looking token inside stored email/evidence text
         (e.g. a threat-intelligence match description).
    Returns the first IP string found, or None if this case's evidence
    contains no IP at all (e.g. a case escalated from a URL or file check,
    which never produces network/IP evidence).
    """
    try:
        for row in (db.get_network_analysis(investigation_id) or []):
            ip = row.get("destination_ip") or row.get("source_ip")
            if ip:
                return ip
        for row in (db.get_geolocation_analysis(investigation_id) or []):
            if row.get("ip_address"):
                return row["ip_address"]
        compiled = forensic_engine.compile_investigation(investigation_id)
        if compiled:
            text_blobs = [e.get("indicators") or "" for e in (compiled.get("email") or [])]
            text_blobs += [ev.get("description") or "" for ev in (compiled.get("evidence") or [])]
            for blob in text_blobs:
                match = _IPV4_RE.search(blob)
                if match:
                    return match.group(0)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

db.init_db()

if "current_investigation_id" not in st.session_state:
    st.session_state.current_investigation_id = None


# ---------------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------------

st.sidebar.markdown(
    '<div class="tt-nav-brand">'
    '<div class="tt-nav-brand-icon">🛡️</div>'
    '<div><div class="tt-nav-brand-title">ThreatTrace</div>'
    '<div class="tt-nav-brand-sub">AI Threat Detection &amp; Digital Forensics</div></div>'
    '</div>',
    unsafe_allow_html=True
)
st.sidebar.divider()

# CHANGE 1 — sidebar navigation replaced to match the reference screenshot
# exactly (8 items, new labels/icons). This is a rename/restyle of the same
# st.sidebar.radio mechanism only — every remaining page's routing branch
# below is updated to match these exact new label strings, and the page
# content those branches render is untouched.
st.markdown("""
<style>
div[data-testid="stSidebar"] {
    min-width: 260px;
    max-width: 260px;
}

div[data-testid="stSidebar"] > div {
    padding-top: 1.5rem;
}
div[data-testid="stSidebar"] button {
    text-align: left;
    border: none;
    border-radius: 8px;
    margin: 2px 0;
    background-color: #123B66;
}

div[data-testid="stSidebar"] button:hover {
    background-color: rgba(59, 130, 246, 0.15);
}
</style>
""", unsafe_allow_html=True)
NAV_ITEMS = [
    "🔲 Dashboard", "🔍 Analyze", "🛡️ AI Risk", "☰ IOCs",
    "🌐 Network Intelligence", "🕸️ Investigation Graph", "🕐 Timeline",
    "📄 Reports",
]

# CHANGE 2 — consume the escalation "switch page" flag BEFORE the radio
# widget below is instantiated. This is the only safe way to change a
# widget's selection: setting session_state[key] after the widget already
# exists this run does nothing (and mutating a bound widget key directly is
# unsafe/unsupported), so this must happen here, pre-widget, every run.
if st.session_state.pop("switch_to_investigation", False):
    st.session_state["nav"] = "🛡️ AI Risk"

if "nav" not in st.session_state:
    st.session_state["nav"] = NAV_ITEMS[0]
for item in NAV_ITEMS:
    is_active = st.session_state["nav"] == item

    if st.sidebar.button(
        item,
        key=f"nav_btn_{item}",
        use_container_width=True,
       type="secondary"
    ):
        st.session_state["nav"] = item
        st.rerun()

nav = st.session_state["nav"]
st.sidebar.divider()
st.sidebar.markdown("**Case**")

investigations = db.list_investigations()
inv_options = {f"INV-{i['id']:04d} — {i['case_name']}": i["id"] for i in investigations}

with st.sidebar.form("new_investigation_form", clear_on_submit=True):
    new_case_name = st.text_input("New case name", placeholder="e.g. Suspicious Vendor Email")
    submitted = st.form_submit_button("➕ Create Investigation")
    if submitted and new_case_name.strip():
        new_id = db.create_investigation(new_case_name.strip())
        st.session_state.current_investigation_id = new_id
        st.rerun()

if inv_options:
    labels = list(inv_options.keys())
    default_idx = 0
    if st.session_state.current_investigation_id:
        for idx, (label, iid) in enumerate(inv_options.items()):
            if iid == st.session_state.current_investigation_id:
                default_idx = idx
                break
    chosen_label = st.sidebar.selectbox("Active investigation", labels, index=default_idx)
    st.session_state.current_investigation_id = inv_options[chosen_label]
else:
    st.sidebar.info("No investigations yet. Create one above, load the demo, or escalate a "
                     "result from Analyze Evidence.")

if st.sidebar.button("🚀 Load Demo Investigation", use_container_width=True):
    from modules import demo_loader
    demo_id = demo_loader.load_demo_investigation()
    st.session_state.current_investigation_id = demo_id
    st.rerun()

if st.session_state.current_investigation_id:
    if st.sidebar.button("🗑️ Delete Active Investigation", use_container_width=True):
        db.delete_investigation(st.session_state.current_investigation_id)
        st.session_state.current_investigation_id = None
        st.rerun()

st.sidebar.divider()
st.sidebar.markdown("**SYSTEM STATUS**")

# Real (not decorative) status checks — each one is a genuine probe of the
# corresponding subsystem, not a hardcoded "always online" indicator.
try:
    _ai_engine_online = email_detector.load_model() is not None
except Exception:
    _ai_engine_online = False
try:
    _ti_online = threat_intelligence.get_stats().get("total", 0) > 0
except Exception:
    _ti_online = False
try:
    db.list_investigations()
    _db_connected = True
except Exception:
    _db_connected = False

for label, ok in [("AI Engine", _ai_engine_online), ("Threat Intelligence", _ti_online),
                   ("Database", _db_connected)]:
    dot_class = "status-on" if ok else "status-off"
    state_text = "Online" if ok else "Offline"
    st.sidebar.markdown(
        f'<div class="status-line"><span class="status-dot {dot_class}"></span>'
        f'{label} {state_text}</div>', unsafe_allow_html=True
    )

st.sidebar.caption("Prototype for educational/research use only. Not a production security product.")

current_id = st.session_state.current_investigation_id


# ---------------------------------------------------------------------------
# TOP BAR
# ---------------------------------------------------------------------------

_tb_col1, _tb_col2 = st.columns([3, 1])
with _tb_col1:
    search_query = st.text_input("Search", key="_topbar_search", label_visibility="collapsed",
                                  placeholder="🔎 Search cases, IOCs, domains…")
with _tb_col2:
    st.markdown('<div class="topbar-right" style="text-align:right;">🔔 &nbsp; 👤 Investigator</div>',
                unsafe_allow_html=True)
st.markdown(f'<div style="border-bottom:1px solid {BORDER};margin-bottom:16px;"></div>',
            unsafe_allow_html=True)

if search_query and search_query.strip():
    q = search_query.strip().lower()
    matched_cases = [i for i in investigations if q in i["case_name"].lower()]
    matched_ti = threat_intelligence.search_indicator(search_query.strip())
    with st.expander(f"🔎 Search results for \"{search_query}\"", expanded=True):
        if matched_cases:
            st.write("**Matching investigations:**")
            st.dataframe(pd.DataFrame(matched_cases)[["id", "case_name", "risk_level", "overall_risk"]],
                         use_container_width=True, hide_index=True)
        if matched_ti:
            st.write("**Matching threat intelligence indicators:**")
            st.dataframe(pd.DataFrame(matched_ti), use_container_width=True, hide_index=True)
        if not matched_cases and not matched_ti:
            st.caption("No matching investigations or indicators found.")


# ---------------------------------------------------------------------------
# Dashboard metric helpers — real aggregation over existing DB getters only
# ---------------------------------------------------------------------------

def _compute_dashboard_metrics(all_investigations):
    """
    - high_critical: investigations with risk_level HIGH or CRITICAL.
    - ioc_count: "Threat Intelligence" evidence rows recorded across every case.
    - active_incidents: investigations whose real `status` column is 'OPEN'.
    """
    ioc_count = 0
    for inv in all_investigations:
        for ev in db.get_evidence(inv["id"]):
            if ev.get("evidence_type") == "Threat Intelligence":
                ioc_count += 1
    high_critical = len([i for i in all_investigations if i["risk_level"] in ("HIGH", "CRITICAL")])
    active_incidents = len([i for i in all_investigations if (i.get("status") or "OPEN") == "OPEN"])
    return high_critical, ioc_count, active_incidents


def _threat_activity_last_7_days(all_investigations):
    if len(all_investigations) < 3:
        return None

    def _to_date(ts):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(ts, fmt).date()
            except Exception:
                continue
        return None

    today = datetime.now().date()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    distinct_days = set()
    buckets = {d: {"High": 0, "Medium": 0, "Low": 0} for d in days}

    for inv in all_investigations:
        d = _to_date(inv.get("created_at") or "")
        if d is None or d not in buckets:
            continue
        distinct_days.add(d)
        level = inv.get("risk_level")
        if level in ("HIGH", "CRITICAL"):
            buckets[d]["High"] += 1
        elif level == "MEDIUM":
            buckets[d]["Medium"] += 1
        else:
            buckets[d]["Low"] += 1

    if len(distinct_days) < 2:
        return None

    return pd.DataFrame([
        {"Day": d.strftime("%b %d"), "High": buckets[d]["High"],
         "Medium": buckets[d]["Medium"], "Low": buckets[d]["Low"]}
        for d in days
    ])


# ---------------------------------------------------------------------------
# PAGE: Dashboard
# ---------------------------------------------------------------------------

if nav == "🔲 Dashboard":
    page_header("Threat Intelligence Dashboard", "Monitor threats, investigations and forensic activity")
    disclaimer("Prototype risk scores are heuristic/ML estimates for demonstration purposes only.")

    all_inv = db.list_investigations()
    high_critical, ioc_count, active_incidents = _compute_dashboard_metrics(all_inv)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Investigations", len(all_inv))
    c2.metric("High / Critical Threats", high_critical)
    c3.metric("IOC / Evidence Count", ioc_count)
    c4.metric("Active / Recent Incidents", active_incidents)

    st.divider()
    section_header("Threat Activity")
    activity_df = _threat_activity_last_7_days(all_inv)
    if activity_df is not None:
        fig = px.bar(activity_df, x="Day", y=["High", "Medium", "Low"], barmode="stack",
                     color_discrete_map={"High": RED, "Medium": AMBER, "Low": GREEN})
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                           legend_title_text="", font_color="#cbd5e1")
        st.plotly_chart(fig, use_container_width=True)
    else:
        empty_state("NOT ENOUGH DATA FOR A TREND",
                     "This fills in as investigations are created across multiple days.", "📈")

    st.divider()
    section_header("Recent Investigations")
    if all_inv:
        recent = sorted(all_inv, key=lambda i: i["created_at"], reverse=True)[:8]
        rows = [{
            "Case ID": f"INV-{i['id']:04d}",
            "Case Name": i["case_name"],
            "Risk": i["overall_risk"],
            "Risk Level": i["risk_level"],
            "Status": i.get("status") or "OPEN",
            "Created": i["created_at"],
        } for i in recent]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        empty_state("NO ACTIVE INVESTIGATION",
                     "Select or create an investigation to begin forensic analysis.", "📁")


# ---------------------------------------------------------------------------
# PAGE: Analyze Evidence  (Protection Mode — no case required)
# ---------------------------------------------------------------------------

elif nav == "🔍 Analyze":
    page_header("Analyze Evidence", "Ingest and analyze a suspicious email, URL, or file.")
    disclaimer("Quick AI threat check. This is a prototype screening tool, not a guarantee of "
               "safety — when in doubt, don't click, open, or reply.")

    if "_analyze_choice" not in st.session_state:
        st.session_state["_analyze_choice"] = "EMAIL"

    c1, c2, c3 = st.columns(3)
    choice_map = {"EMAIL": (c1, "📧", "Analyze suspicious email content"),
                  "URL": (c2, "🔗", "Analyze suspicious URL"),
                  "FILE": (c3, "📎", "Analyze uploaded evidence/document")}
    for key, (col, icon, desc) in choice_map.items():
        with col:
            active = st.session_state["_analyze_choice"] == key
            st.markdown(
                f'<div class="tt-select-card {"active" if active else ""}">'
                f'<div class="tt-select-icon">{icon}</div>'
                f'<div class="tt-card-title">{key}</div>'
                f'<div class="tt-card-sub">{desc}</div></div>',
                unsafe_allow_html=True
            )
            if st.button(f"Select {key}", key=f"select_{key}", use_container_width=True):
                st.session_state["_analyze_choice"] = key
                st.rerun()

    st.divider()
    choice = st.session_state["_analyze_choice"]

    def _run_with_progress(steps_and_fns):
        """
        Real, honest progress: each step's label is only marked complete
        AFTER its corresponding real backend call has actually returned.
        Returns the final step's result.
        """
        result = None
        with st.status("Running analysis…", expanded=True) as status:
            for label, fn in steps_and_fns:
                st.write(label)
                result = fn()
            status.update(label="Analysis complete", state="complete", expanded=False)
        return result

    def _render_result(result, key_prefix):
        st.divider()
        threat_detected = result.get("classification", "BENIGN") in ("PHISHING", "SCAM", "IMPERSONATION")
        section_header("Threat Assessment")
        c1, c2, c3 = st.columns(3)
        c1.metric("Risk Score", f"{result['risk_score']} / 100")
        verdict = (
            "SAFE" if result.get("risk_score", 0) <= 30
            else "SUSPICIOUS" if result.get("risk_score", 0) <= 60
            else "DANGEROUS"
        )

        c2.markdown(f"**Verdict**<br>{risk_badge(verdict)}", unsafe_allow_html=True)
        c3.write(f"**Classification**\n\n`{result['classification']}`")
        confidence = (result.get("raw") or {}).get("confidence")
        if confidence is not None:
            st.caption(f"Confidence (detector-reported): {confidence}% — a separate figure from "
                       f"the risk score above, never averaged into it.")

        section_header("Detected Indicators")
        indicator_lines = list(result.get("indicators", result.get("reasons", [])))
        if indicator_lines:
            for ind in indicator_lines:
                st.markdown(f"- {ind}")
        else:
            empty_state("NO INDICATORS DETECTED", icon="🔍")

        classification = result.get("classification", "BENIGN")
        risk_score = result.get("risk_score", 0)
        if classification in ("PHISHING", "SCAM", "IMPERSONATION") or risk_score > 30:
            action_message = "Action Needed — suspicious activity detected."
        else:
            action_message = "No action needed — no significant threat detected."

        if risk_score > 60:
            st.error(f"⚠️ {action_message}")
        elif risk_score > 30:
            st.warning(f"⚠️ {action_message}")
        else:
            st.success(f"✅ {action_message}")

        st.divider()
        if st.button(
            "🔎 ESCALATE TO INVESTIGATION",
             key=f"{key_prefix}_escalate",
             type="primary"
):
            classification = result.get("classification", "UNKNOWN")
            summary = result.get(
                "summary",
                f"{classification} email threat detected"
            )

            case_name = (
                f"Escalated from Protection Mode — "
                f"{summary[:50]}"
            )
            inv_id = db.create_investigation(case_name)

            if key_prefix == "email":
                raw = result.get("raw", result)

                db.insert_email_analysis(
                    inv_id,
                    raw.get("sender", result.get("sender", "")),
                    raw.get("receiver", result.get("receiver", "")),
                    raw.get("subject", result.get("subject", "")),
                    raw.get(
                        "classification",
                        result.get("classification", "UNKNOWN")
                    ),
                    raw.get(
                        "risk_score",
                        result.get("risk_score", 0)
                    ),
                    "; ".join(
                        raw.get(
                            "indicators",
                            result.get("indicators", [])
                        )
                    )
                )

            elif key_prefix == "url":
                reasons = result.get(
                    "reasons",
                    result.get("indicators", [])
                )

                db.insert_email_analysis(
                    inv_id,
                    None,
                    None,
                    f"URL Check: {summary}",
                    result.get("classification", "UNKNOWN"),
                    result.get("risk_score", 0),
                    "; ".join(reasons)
                )

            elif key_prefix == "file":
                raw = result.get("raw")

                if raw:
                    db.insert_document_analysis(
                        inv_id,
                        raw.get("document_name", summary),
                        raw.get("document_type", "ID_CARD"),
                        raw.get("ocr_text", ""),
                        raw.get("authenticity_score", 0),
                        None,
                        raw.get(
                            "risk_score",
                            result.get("risk_score", 0)
                        ),
                        "; ".join(
                            raw.get("indicators", [])
                        )
                    )

                else:
                    reasons = result.get(
                        "reasons",
                        result.get("indicators", [])
                    )

                    risk_score = result.get(
                        "risk_score",
                        0
                    )

                    db.insert_document_analysis(
                        inv_id,
                        summary,
                        "OTHER_FILE",
                        "",
                        max(0, 100 - risk_score),
                        None,
                        risk_score,
                        "; ".join(reasons)
                    )

           
            # CHANGE 2 fix: store the new case, set the switch flag (consumed
            # BEFORE the sidebar radio widget is created — see above the
            # widget instantiation), then rerun. This is what actually moves
            # the user to the Investigation page; setting current_investigation_id
            # alone (the old behavior) only changed which case was active, not
            # which page was showing.
            st.session_state.current_investigation_id = inv_id
            st.session_state["switch_to_investigation"] = True
            st.success(f"Created INV-{inv_id:04d} from this result. Opening AI Risk…")
            st.rerun()

    if choice == "EMAIL":
        with st.form("protection_email_form"):
            sender_in = st.text_input("Sender (optional)")
            subject_in = st.text_input("Subject (optional)")
            body_in = st.text_area("Email body", height=180)
            submitted = st.form_submit_button("Start Analysis →", type="primary")
            if submitted:
                if body_in.strip():
                    def _step1():
                        return email_detector.parse_plain_text(body_in, sender_in, "", subject_in)

                    parsed_holder = {}
                    result = _run_with_progress([
                        ("INGESTING EVIDENCE", lambda: parsed_holder.setdefault("v", _step1())),
                        ("EXTRACTING INDICATORS / AI ANALYSIS",
                         lambda: parsed_holder.setdefault("r", email_detector.analyze_email(parsed_holder["v"]))),
                        ("RISK ASSESSMENT", lambda: parsed_holder["r"]),
                    ])
                    st.session_state["_protection_email_result"] = result
                else:
                    st.error("Paste some email text before checking.")

        result = st.session_state.get("_protection_email_result")
        if result:
            _render_result(result, "email")

    elif choice == "URL":
        url_in = st.text_input(
            "URL to check",
            placeholder="e.g. http://secure-verify-account.com/login"
        )

        if st.button("Start Analysis →", type="primary", key="url_start") and url_in.strip():
            holder = {}

            result = _run_with_progress([
                (
                    "INGESTING EVIDENCE",
                    lambda: holder.setdefault("v", url_in.strip())
                ),
                (
                    "EXTRACTING INDICATORS / AI ANALYSIS",
                    lambda: holder.setdefault(
                        "r",
                        protection_scan.check_url(holder["v"])
                    )
                ),
                (
                    "RISK ASSESSMENT",
                    lambda: holder["r"]
                ),
            ])

            st.session_state["_protection_url_result"] = result

        result = st.session_state.get("_protection_url_result")
        if result:
            _render_result(result, "url")

    elif choice == "FILE":
        file_in = st.file_uploader(
            "File to check",
            type=["png", "jpg", "jpeg", "pdf", "exe", "zip", "js", "docx", "txt"]
        )

        if file_in and st.button("Start Analysis →", type="primary", key="file_start"):
            holder = {}
            file_bytes = file_in.read()
            result = _run_with_progress([
                ("INGESTING EVIDENCE", lambda: holder.setdefault("v", file_bytes)),
                ("EXTRACTING INDICATORS / AI ANALYSIS",
                 lambda: holder.setdefault("r", protection_scan.check_file(holder["v"], file_in.name))),
                ("RISK ASSESSMENT", lambda: holder["r"]),
            ])
            st.session_state["_protection_file_result"] = result

        result = st.session_state.get("_protection_file_result")
        if result:
            _render_result(result, "file")


# ---------------------------------------------------------------------------
# PAGE: AI Risk Analysis
# ---------------------------------------------------------------------------

elif nav == "🛡️ AI Risk":
    page_header("AI Risk Analysis", "Explainable, centrally-computed risk for the active investigation.")
    disclaimer("This is a prototype risk score, not an absolute probability of maliciousness.")

    if not current_id:
        empty_state("NO ACTIVE INVESTIGATION",
                     "Select or create an investigation to begin forensic analysis.", "🗂️")
    else:
        recalc = risk_engine.recalculate_case_risk(current_id)
        module_scores = recalc["module_scores"]
        contributions = recalc["contributions"]
        overall, level = recalc["overall_score"], recalc["risk_level"]

        col_gauge, col_badge = st.columns([2, 1])
        with col_gauge:
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=overall, title={"text": "OVERALL RISK SCORE"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": RED if level in ("HIGH", "CRITICAL") else AMBER},
                    "steps": [
                        {"range": [0, 30], "color": "#14532d"},
                        {"range": [30, 60], "color": "#713f12"},
                        {"range": [60, 80], "color": "#7f1d1d"},
                        {"range": [80, 100], "color": "#450a0a"},
                    ],
                }
            ))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#e5e7eb", height=300)
            st.plotly_chart(fig, use_container_width=True)
        with col_badge:
            st.markdown(f"### {risk_badge(level)}", unsafe_allow_html=True)
            st.caption("Risk Level")
            if recalc["threat_intel_hits"]:
                st.caption(f"🚨 {len(recalc['threat_intel_hits'])} real threat-intelligence "
                           f"match(es) contributed to this score.")

        section_header("Risk Explanation")
        for line in recalc["explanation"]:
            st.markdown(f"- {line}" if not line.startswith("Key Risk") else f"**{line}**")

        section_header("Module Contributions")
        st.caption("RISK is each module's own 0–100 score below; it is never averaged with "
                   "detector CONFIDENCE values shown elsewhere in the app.")
        cols = st.columns(max(len(contributions), 1))
        for col, (module, c) in zip(cols, contributions.items()):
            with col:
                card(module.replace("_", " ").upper(),
                     body_html=f'<div style="font-size:1.4rem;font-weight:700;color:#e5e7eb;">{c["score"]}</div>',
                     sub=f"weight {c['weight']:.2f} → contributes {c['contribution']}")
        if not contributions:
            empty_state("NO MODULE SCORES AVAILABLE", "Add evidence to this investigation.", "📊")

        labels = ["Email", "Network", "Document", "Identity", "Geolocation", "Threat Intel"]
        keys = ["email", "network", "document", "identity", "geolocation", "threat_intelligence"]
        values = [module_scores.get(k) or 0 for k in keys]
        fig2 = px.bar(x=labels, y=values, range_y=[0, 100], color=values, color_continuous_scale="Reds")
        fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                           font_color="#cbd5e1", coloraxis_showscale=False)
        st.plotly_chart(fig2, use_container_width=True)

        section_header("Related Activity")
        render_correlation_panel(recalc.get("correlation"))


# ---------------------------------------------------------------------------
# PAGE: IOC Intelligence
# ---------------------------------------------------------------------------

elif nav == "☰ IOCs":
    page_header("IOC Intelligence", "Indicators of Compromise — Type, Indicator, Status, Severity, "
                "Threat Type only. Reputation, ASN, WHOIS, and malware-family data are not "
                "implemented in this build and are never fabricated.")

    if current_id:
        section_header(f"IOCs Matched — INV-{current_id:04d}")
        recalc = risk_engine.recalculate_case_risk(current_id)
        hits = recalc["threat_intel_hits"]
        if hits:
            rows = []
            for h in hits:
                status_label = {"known threat": "MALICIOUS", "suspicious": "SUSPICIOUS"}.get(
                    h.get("status"), "UNKNOWN")
                rows.append({
                    "Type": h.get("indicator_type", "").upper(),
                    "Indicator": h.get("indicator"),
                    "Status": status_label,
                    "Severity": h.get("severity") or "—",
                    "Threat Type": h.get("threat_type") or "—",
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            empty_state("NO IOC MATCHES AVAILABLE",
                         "No threat-intelligence matches found for this investigation's evidence.", "⌁")
    else:
        st.caption("Select an investigation from the sidebar to see case-specific IOC matches, "
                   "or browse the full reference dataset below.")

    st.divider()
    section_header("Local Threat Intelligence Dataset")
    stats = threat_intelligence.get_stats()
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Indicators", stats["total"])
    c2.metric("Types Covered", len(stats["by_type"]))
    c3.metric("Severity Levels", len(stats["by_severity"]))

    all_indicators = threat_intelligence.get_all_indicators()
    if all_indicators:
        df_ti = pd.DataFrame(all_indicators)
        fig = px.bar(df_ti["threat_type"].value_counts().reset_index(), x="threat_type", y="count")
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                           font_color="#cbd5e1")
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(df_ti, use_container_width=True, hide_index=True)
    else:
        empty_state("NO IOC DATA AVAILABLE", icon="⌁")


# ---------------------------------------------------------------------------
# PAGE: Network Intelligence  (Network Detection + Geolocation)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# PAGE: Network Intelligence  (Network Detection + Geolocation)
# ---------------------------------------------------------------------------

elif nav == "🌐 Network Intelligence":
    page_header(
        "Network Intelligence",
        "Network flow analysis and approximate IP geolocation."
    )

    if not current_id:
        empty_state(
            "NO ACTIVE INVESTIGATION",
            "Select or create an investigation to begin forensic analysis.",
            "🗂️"
        )

    else:
        tab_flows, tab_geo = st.tabs(
            ["📡 Network Detection", "🌍 Geolocation"]
        )

        # ===================================================================
        # TAB 1: NETWORK DETECTION
        # ===================================================================

        with tab_flows:

            # Do not imply that network investigation is already running
            # when there is no network-flow evidence for this case.
            if (
                not _case_has_network_evidence(current_id)
                and st.session_state.get("_last_network_analyzed") is None
            ):
                empty_state(
                    "NETWORK INVESTIGATION CANNOT PROCEED",
                    "No network evidence is available for this case. Upload a "
                    "network flow CSV or load demo network data below to add "
                    "real evidence.",
                    "🚫"
                )

            colU, colD = st.columns([2, 1])

            with colU:
                csv_file = st.file_uploader(
                    "Upload network flow CSV",
                    type=["csv"]
                )

            with colD:
                st.write("")
                st.write("")
                use_demo = st.button(
                    "📊 Load Demo Network Data",
                    use_container_width=True
                )

            flow_df = None

            if csv_file:
                try:
                    flow_df = pd.read_csv(csv_file)
                except Exception as e:
                    st.error(f"Could not read CSV: {e}")

            elif use_demo:
                flow_df = network_detector.load_demo_data(25)

            if flow_df is not None:

                missing = network_detector.validate_columns(flow_df)

                if missing:
                    st.error(
                        f"Uploaded CSV is missing required columns: {missing}"
                    )

                else:

                    if st.button(
                        "🔍 Analyze Network Flows",
                        type="primary"
                    ):

                        analyzed = network_detector.analyze_flows(flow_df)

                        for _, row in analyzed.iterrows():
                            db.insert_network_analysis(
                                current_id,
                                row["source_ip"],
                                row["destination_ip"],
                                row["protocol"],
                                row["classification"],
                                row["risk_score"],
                                row["indicators"]
                            )

                        dest_ips = (
                            analyzed["destination_ip"]
                            .dropna()
                            .unique()
                            .tolist()
                        )

                        ti_hits = (
                            threat_intelligence
                            .correlate_evidence_indicators(
                                network_destination_ips=dest_ips
                            )
                        )

                        st.session_state["_last_network_analyzed"] = analyzed
                        st.session_state["_last_network_ti_hits"] = ti_hits

                        risk_engine.recalculate_case_risk(current_id)

                        st.rerun()

            # ---------------------------------------------------------------
            # Network analysis results
            # ---------------------------------------------------------------

            analyzed = st.session_state.get(
                "_last_network_analyzed"
            )

            if analyzed is not None:

                st.divider()

                summary = network_detector.summarize_flows(analyzed)

                section_header("Network Risk / Traffic Summary")

                c1, c2, c3, c4, c5 = st.columns(5)

                c1.metric("Total Flows", summary["total"])
                c2.metric("Benign", summary["benign"])
                c3.metric("Suspicious", summary["suspicious"])
                c4.metric("Malicious", summary["malicious"])
                c5.metric("Anomalous", summary["anomalous"])

                st.caption(
                    f"Average flow risk: {summary['avg_risk']}/100"
                )

                colP, colPo = st.columns(2)

                with colP:
                    st.write("**Protocols:**")

                    st.dataframe(
                        analyzed["protocol"]
                        .value_counts()
                        .reset_index(),
                        use_container_width=True,
                        hide_index=True
                    )

                with colPo:
                    st.write("**Destination Ports:**")

                    st.dataframe(
                        analyzed["destination_port"]
                        .value_counts()
                        .reset_index(),
                        use_container_width=True,
                        hide_index=True
                    )

                fig = px.histogram(
                    analyzed,
                    x="classification",
                    color="classification",
                    title=(
                        "Normal vs Suspicious vs Malicious vs "
                        "Anomalous Traffic"
                    )
                )

                fig.update_layout(
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="#cbd5e1"
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

                if summary["top_destinations"]:

                    st.write("**Top Destination IPs (avg risk):**")

                    for dest, risk in summary["top_destinations"]:
                        st.markdown(
                            f"- `{dest}` — avg risk **{round(risk, 1)}**"
                        )

                ti_hits = (
                    st.session_state.get("_last_network_ti_hits")
                    or []
                )

                if ti_hits:

                    st.write(
                        "**Threat Intelligence Correlation:**"
                    )

                    st.dataframe(
                        pd.DataFrame(ti_hits),
                        use_container_width=True,
                        hide_index=True
                    )

                st.dataframe(
                    analyzed,
                    use_container_width=True,
                    hide_index=True
                )

            # ---------------------------------------------------------------
            # Network Evidence Log
            # ---------------------------------------------------------------

            st.divider()

            section_header("Network Evidence Log")

            records = db.get_network_analysis(current_id)

            if records:
                st.dataframe(
                    pd.DataFrame(records),
                    use_container_width=True,
                    hide_index=True
                )
            else:
                empty_state(
                    "NO NETWORK EVIDENCE AVAILABLE",
                    icon="📡"
                )

        # ===================================================================
        # TAB 2: GEOLOCATION
        # ===================================================================

        with tab_geo:

            # Check whether this case already contains a usable IP.
            _usable_ip = _find_usable_ip_in_case(current_id)

            if not _usable_ip:

                st.error(
                    "🚫 No IP Address Available"
                )

                st.caption(
                    "No IP address was found in the provided evidence for "
                    "this case. You can still enter an IP address manually "
                    "to investigate its location."
                )

            else:

                st.caption(
                    f"IP found in this case's evidence: `{_usable_ip}`"
                )

            # This remains OUTSIDE the if/else so manual IP investigation
            # is always available.
            use_real_lookup = st.checkbox(
                "Use live IP geolocation API (ip-api.com) "
                "instead of the offline demo dataset",
                value=False,
                help=(
                    "Off by default so the app works with no internet/API key. "
                    "When off, results come from a fixed local demo dataset "
                    "and will NOT reflect the IP's real-world location."
                )
            )

            col1, col2 = st.columns([3, 1])

            with col1:

                ip_input = st.text_input(
                    "IP address to look up",
                    value=_usable_ip if _usable_ip else "",
                    placeholder="e.g. 91.219.237.100"
                )

            with col2:

                st.write("")
                st.write("")

                lookup_btn = st.button(
                    "🔍 Analyze IP",
                    type="primary",
                    use_container_width=True
                )

            if lookup_btn and ip_input:

                result = geolocation.lookup_ip(
                    ip_input.strip(),
                    use_external_api=use_real_lookup
                )

                if not result.get("valid"):

                    st.error(
                        result.get("error")
                    )

                else:

                    if result.get("source") == "demo_fallback":

                        st.info(
                            "📍 OFFLINE / DEMO FALLBACK DATA — this does not "
                            "reflect the IP's real location. Check the box "
                            "above to use the live API."
                        )

                    risk_score, risk_indicators = (
                        geolocation.score_geolocation_risk(result)
                    )

                    st.session_state["_last_geo_result"] = result

                    st.session_state["_last_geo_risk"] = (
                        risk_score,
                        risk_indicators
                    )

            # ---------------------------------------------------------------
            # Geolocation Results
            # ---------------------------------------------------------------

            geo_result = st.session_state.get(
                "_last_geo_result"
            )

            if geo_result:

                risk_score, risk_indicators = (
                    st.session_state.get(
                        "_last_geo_risk",
                        (0, [])
                    )
                )

                st.divider()

                st.caption(
                    "Approximate geolocation provides contextual evidence "
                    "only — this is NOT the exact physical location of a "
                    "person or device."
                )

                c1, c2, c3, c4 = st.columns(4)

                c1.metric(
                    "Country",
                    geo_result.get("country")
                )

                c2.metric(
                    "Region",
                    geo_result.get("region")
                )

                c3.metric(
                    "City",
                    geo_result.get("city")
                )

                c4.metric(
                    "Risk Signal",
                    f"{risk_score}/100"
                )

                st.write(
                    "**ISP/Organization:**",
                    geo_result.get("isp")
                )

                st.caption(
                    f"Data source: {geo_result.get('source')}"
                )

                for ind in risk_indicators:
                    st.markdown(f"- {ind}")
                if (
                    geo_result.get("latitude") is not None
                    and geo_result.get("longitude") is not None
                ):

                    map_df = pd.DataFrame([{
                        "lat": float(geo_result["latitude"]),
                        "lon": float(geo_result["longitude"]),
                        "label": (
                            f"{geo_result['ip_address']} — "
                            f"{geo_result['city']}, "
                            f"{geo_result['country']}"
                        )
                    }])

                    st.write("### 📍 Approximate IP Location")

                    st.map(
                        map_df,
                        latitude="lat",
                        longitude="lon",
                        size=200,
                        use_container_width=True
                    )

                    st.caption(
                        f"📍 Approximate location: "
                        f"{geo_result.get('city')}, "
                        f"{geo_result.get('country')}"
                    )

                if st.button(
                    "💾 Save Geolocation Evidence to Investigation"
                ):

                    db.insert_geolocation_analysis(
                        current_id,
                        geo_result["ip_address"],
                        geo_result.get("country"),
                        geo_result.get("region"),
                        geo_result.get("city"),
                        geo_result.get("latitude"),
                        geo_result.get("longitude"),
                        risk_score,
                        "; ".join(risk_indicators)
                    )

                    risk_engine.recalculate_case_risk(
                        current_id
                    )

                    st.success(
                        "Geolocation evidence saved."
                    )

                    st.rerun()

            # ---------------------------------------------------------------
            # Geolocation Evidence Log
            # ---------------------------------------------------------------

            st.divider()

            section_header(
                "Geolocation Evidence Log"
            )

            records = db.get_geolocation_analysis(
                current_id
            )

            if records:

                st.dataframe(
                    pd.DataFrame(records),
                    use_container_width=True,
                    hide_index=True
                )

            else:

                empty_state(
                    "NO GEOLOCATION EVIDENCE AVAILABLE",
                    icon="🌍"
                )
       

# ---------------------------------------------------------------------------
# PAGE: Investigation Graph
# ---------------------------------------------------------------------------

elif nav == "🕸️ Investigation Graph":
    page_header("Investigation Graph", "How this investigation's evidence connects — built "
                "directly from stored evidence, never inferred beyond it.")

    if not current_id:
        empty_state("NO ACTIVE INVESTIGATION",
                     "Select or create an investigation to begin forensic analysis.", "🗂️")
    else:
        compiled = forensic_engine.compile_investigation(current_id)
        graph = forensic_engine.build_evidence_graph(compiled)

        render_relationship_graph(graph)

        section_header("Typed Relationships")
        if graph.get("relationship_edges"):
            rows = [{"Source": r["source"], "Relationship": r["relationship"].replace("_", " "),
                     "Target": r["target"]} for r in graph["relationship_edges"]]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        elif graph.get("edges"):
            rows = [{"Source": s, "Target": t} for s, t in graph["edges"]]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            empty_state("NO RELATIONSHIP DATA AVAILABLE", icon="◎")


# ---------------------------------------------------------------------------
# PAGE: Forensic Timeline
# ---------------------------------------------------------------------------

elif nav == "🕐 Timeline":
    page_header("Forensic Timeline", "Chronological view of every analysis event for this "
                "investigation — TIME, SOURCE, and EVENT, straight from stored evidence.")

    if not current_id:
        empty_state("NO ACTIVE INVESTIGATION",
                     "Select or create an investigation to begin forensic analysis.", "🗂️")
    else:
        compiled = forensic_engine.compile_investigation(current_id)
        events = timeline_utils.build_timeline(
            compiled["email"], compiled["network"], compiled["document"],
            compiled["geolocation"], compiled["evidence"]
        )
        render_timeline(events)

        if events:
            st.divider()
            section_header("Timeline Overview")
            tdf = timeline_utils.timeline_to_dataframe(events)
            fig = px.scatter(tdf, x="time", y="category", color="category",
                              size=[max(r, 5) for r in tdf["risk"]], hover_data=["event"])
            fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                               font_color="#cbd5e1")
            st.plotly_chart(fig, use_container_width=True)


# ---------------------------------------------------------------------------
# PAGE: Evidence
# ---------------------------------------------------------------------------

elif nav == "▤ Evidence":
    page_header("Evidence", "All evidence collected for this investigation, organized by category.")

    if not current_id:
        empty_state("NO ACTIVE INVESTIGATION",
                     "Select or create an investigation to begin forensic analysis.", "🗂️")
    else:
        compiled = forensic_engine.compile_investigation(current_id)
        counts = forensic_engine.evidence_summary_counts(compiled)
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Email", counts["email_count"])
        c2.metric("Network", counts["network_count"])
        c3.metric("Document", counts["document_count"])
        c4.metric("Geolocation", counts["geolocation_count"])
        c5.metric("Threat Intel / Other", counts["evidence_count"])

        tabs = st.tabs(["📧 Email Evidence", "🌐 Network Evidence", "🪪 Document Evidence",
                        "🚩 Threat Intelligence", "🌍 Geolocation"])

        with tabs[0]:
            if compiled["email"]:
                st.dataframe(pd.DataFrame(compiled["email"]), use_container_width=True, hide_index=True)
            else:
                empty_state("NO EMAIL EVIDENCE AVAILABLE", icon="📧")
            with st.expander("➕ Add Email Evidence"):
                sub1, sub2, sub3 = st.tabs(["Upload .eml", "Upload .txt", "Paste Email"])
                parsed = None
                with sub1:
                    eml_file = st.file_uploader("Upload .eml file", type=["eml"], key="eml_upl")
                    if eml_file:
                        try:
                            parsed = email_detector.parse_eml_bytes(eml_file.read())
                        except Exception as e:
                            st.error(f"Could not parse uploaded .eml file: {e}")
                with sub2:
                    txt_file = st.file_uploader("Upload .txt file", type=["txt"], key="txt_upl")
                    if txt_file:
                        try:
                            content = txt_file.read().decode("utf-8", errors="ignore")
                            parsed = email_detector.parse_plain_text(content)
                        except Exception as e:
                            st.error(f"Could not read uploaded .txt file: {e}")
                with sub3:
                    with st.form("paste_email_form"):
                        sender_in = st.text_input("Sender (optional)")
                        receiver_in = st.text_input("Receiver (optional)")
                        subject_in = st.text_input("Subject (optional)")
                        body_in = st.text_area("Email body", height=160)
                        paste_submit = st.form_submit_button("Use This Text")
                        if paste_submit:
                            if body_in.strip():
                                parsed = email_detector.parse_plain_text(body_in, sender_in, receiver_in, subject_in)
                            else:
                                st.error("Email body is empty — please paste some email text.")

                if parsed and not parsed.get("error"):
                    st.session_state["_pending_email_parsed"] = parsed

                pending = st.session_state.get("_pending_email_parsed")
                if pending:
                    st.write("**Ready to analyze:**", pending.get("subject") or "(no subject)")
                    if st.button("🔍 Analyze Email", type="primary", key="analyze_email_btn"):
                        result = email_detector.analyze_email(pending)
                        db.insert_email_analysis(
                            current_id, result["sender"], result["receiver"], result["subject"],
                            result["classification"], result["risk_score"], "; ".join(result["indicators"])
                        )
                        ti_hits = threat_intelligence.correlate_evidence_indicators(
                            email_urls=result["urls"], email_sender=result["sender"]
                        )
                        st.session_state["_last_email_result"] = result
                        st.session_state["_last_email_ti_hits"] = ti_hits
                        st.session_state["_pending_email_parsed"] = None
                        risk_engine.recalculate_case_risk(current_id)
                        st.rerun()

                last_result = st.session_state.get("_last_email_result")
                if last_result:
                    st.write(f"**Classification:** `{last_result['classification']}` &nbsp; "
                             f"**Risk Score:** {last_result['risk_score']}/100 &nbsp; "
                             f"**Confidence:** {last_result['confidence']}%")
                    for ind in last_result["indicators"]:
                        st.markdown(f"- {ind}")
                    ti_hits = st.session_state.get("_last_email_ti_hits") or []
                    if ti_hits:
                        st.write("**Threat Intelligence Correlation:**")
                        st.dataframe(pd.DataFrame(ti_hits), use_container_width=True, hide_index=True)

        with tabs[1]:
            if compiled["network"]:
                st.dataframe(pd.DataFrame(compiled["network"]), use_container_width=True, hide_index=True)
            else:
                empty_state("NO NETWORK EVIDENCE AVAILABLE", icon="🌐")
            st.caption("Add network flow evidence from the ◈ Network Intelligence page.")

        with tabs[2]:
            if compiled["document"]:
                st.dataframe(pd.DataFrame(compiled["document"]), use_container_width=True, hide_index=True)
            else:
                empty_state("NO DOCUMENT EVIDENCE AVAILABLE", icon="🪪")
            with st.expander("➕ Add Document Evidence"):
                if not document_detector.is_ocr_available():
                    st.warning("⚠ OCR engine unavailable — using fallback heuristics without extracted text.")
                if not document_detector.is_document_model_available():
                    st.info("ℹ️ Supplementary ML structural model not found — heuristics only.")

                doc_file = st.file_uploader("Upload identity document", type=["png", "jpg", "jpeg", "pdf"],
                                             key="doc_upl")
                doc_type = st.selectbox("Document type", ["ID_CARD", "PASSPORT", "DRIVER_LICENSE"])

                if doc_file:
                    file_bytes = doc_file.read()
                    is_pdf = document_detector.is_pdf_bytes(file_bytes) or doc_file.name.lower().endswith(".pdf")
                    if not is_pdf:
                        st.image(file_bytes, caption="Document Preview", width=300)
                    if st.button("🔍 Screen Document", type="primary", key="screen_doc_btn"):
                        with st.spinner("Processing document and running OCR…"):
                            screening = document_detector.screen_document(file_bytes, doc_file.name, doc_type)
                        st.session_state["_last_doc_screening"] = screening

                screening = st.session_state.get("_last_doc_screening")
                if screening:
                    outcome = (screening.get("risk_level") or "UNKNOWN").split()[0]
                    st.write(f"**Screening Outcome:** {risk_badge(outcome)} &nbsp; "
                             f"Authenticity: {screening['authenticity_score']}/100",
                             unsafe_allow_html=True)
                    st.caption("SCREENING / SUPPORTING EVIDENCE ONLY — not proof a document is "
                               "genuine or fake.")
                    st.write("**Recommendation:**", screening["recommendation"])
                    for ind in screening.get("heuristic_indicators", screening.get("indicators", [])):
                        st.markdown(f"- {ind}")
                    ml = screening.get("ml_screening")
                    if ml and ml.get("available"):
                        st.caption(f"Supplementary ML signal: `{ml['prediction']}` "
                                   f"(confidence {ml['confidence']}%) — not a standalone determination.")

                    with st.form("identity_consistency_form"):
                        colA, colB = st.columns(2)
                        with colA:
                            email_name = st.text_input("Name as it appears in email evidence (optional)")
                            email_org = st.text_input("Organization referenced in email (optional)")
                        with colB:
                            expected_org = st.text_input("Expected organization for this case (optional)")
                            claimed_address = st.text_input("Claimed address (optional)")
                        run_check = st.form_submit_button("Run Identity Consistency Check")
                        if run_check:
                            email_identity = {"name": email_name, "organization": email_org}
                            document_identity = {
                                "name": screening["extracted_fields"].get("Name"),
                                "address": screening["extracted_fields"].get("Address"),
                            }
                            case_context = {"expected_organization": expected_org,
                                             "claimed_address": claimed_address}
                            st.session_state["_last_consistency"] = identity_detector.compare_identities(
                                email_identity, document_identity, case_context
                            )

                    consistency = st.session_state.get("_last_consistency")
                    if consistency:
                        st.metric("Identity Consistency Score",
                                  f"{consistency['identity_consistency_score']}/100")
                        for m in consistency["matches"]:
                            st.markdown(f"- ✅ {m}")
                        for m in consistency["mismatches"]:
                            st.markdown(f"- ⚠️ {m}")

                        if st.button("💾 Save Document Evidence to Investigation"):
                            db.insert_document_analysis(
                                current_id, screening["document_name"], screening["document_type"],
                                screening["ocr_text"], screening["authenticity_score"],
                                consistency["identity_consistency_score"], screening["risk_score"],
                                "; ".join(screening["indicators"] + consistency["mismatches"])
                            )
                            risk_engine.recalculate_case_risk(current_id)
                            st.success("Document evidence saved.")
                            st.session_state["_last_doc_screening"] = None
                            st.session_state["_last_consistency"] = None
                            st.rerun()

        with tabs[3]:
            ti_evidence = [e for e in compiled["evidence"] if e.get("evidence_type") in
                          ("Threat Intelligence", "Correlation")]
            if ti_evidence:
                st.dataframe(pd.DataFrame(ti_evidence), use_container_width=True, hide_index=True)
            else:
                empty_state("NO THREAT INTELLIGENCE EVIDENCE AVAILABLE", icon="🚩")

        with tabs[4]:
            if compiled["geolocation"]:
                st.dataframe(pd.DataFrame(compiled["geolocation"]), use_container_width=True, hide_index=True)
            else:
                empty_state("NO GEOLOCATION EVIDENCE AVAILABLE", icon="🌍")
            st.caption("Add geolocation lookups from the ◈ Network Intelligence page.")


# ---------------------------------------------------------------------------
# PAGE: Reports
# ---------------------------------------------------------------------------

elif nav == "📄 Reports":
    page_header("Forensic Report", "Investigation summary, correlation analysis, and downloadable "
                "PDF report.")

    if not current_id:
        empty_state("NO ACTIVE INVESTIGATION",
                     "Select or create an investigation to begin forensic analysis.", "🗂️")
    else:
        recalc = risk_engine.recalculate_case_risk(current_id)
        inv = recalc["investigation"]

        section_header("Current Investigation")
        c1, c2, c3 = st.columns(3)
        c1.metric("Investigation", f"INV-{inv['id']:04d}")
        c2.metric("Risk Score", f"{recalc['overall_score']}/100")
        c3.markdown(f"**Risk Level**<br>{risk_badge(recalc['risk_level'])}", unsafe_allow_html=True)
        st.caption(inv["case_name"])

        section_header("Related Activity")
        render_correlation_panel(recalc.get("correlation"))

        section_header("Next Investigation Steps")
        render_next_steps_panel(recalc.get("next_steps"))

        st.divider()
        if st.button("📄 Generate Forensic Report", type="primary", use_container_width=True):
            try:
                filepath = report_generator.generate_report_from_recalc(recalc)
                st.session_state["_last_report_path"] = filepath
                st.success(f"Report generated. Overall risk: {recalc['overall_score']}/100 "
                           f"({recalc['risk_level']}).")
            except Exception as e:
                st.error(f"Could not generate PDF report: {e}")

        report_path = st.session_state.get("_last_report_path")
        if report_path and os.path.exists(report_path):
            with open(report_path, "rb") as f:
                st.download_button("⬇️ Download PDF", f, file_name=os.path.basename(report_path),
                                    mime="application/pdf", use_container_width=True)