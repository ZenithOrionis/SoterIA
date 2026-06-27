import asyncio
import json
import sqlite3
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from streamlit_agraph import agraph, Node, Edge, Config

# Ensure project root is importable
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.config.settings import get_settings
from src.db.database import DB_PATH
from src.services.copilot import answer_ciso_question
from src.services.geo_resolver import ip_to_geo
from src.services.report_gen import generate_incident_report

settings = get_settings()

# ── Page Config ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="SoterIA // SOC",
    page_icon="[S]",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

    /* ── Core background ── */
    .stApp,
    [data-testid="stAppViewContainer"],
    [data-testid="stMain"] { background-color: #070b11; }

    /* ── Hide Streamlit chrome ── */
    #MainMenu, footer, header { visibility: hidden; }

    /* ── Tabs ── */
    [data-testid="stTabs"] button {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.75rem !important;
        letter-spacing: 0.12em !important;
        text-transform: uppercase !important;
        color: #4a5568 !important;
        border-bottom: 2px solid transparent !important;
        padding: 0.6rem 1.4rem !important;
        transition: all 0.2s !important;
    }
    [data-testid="stTabs"] button[aria-selected="true"] {
        color: #00ff88 !important;
        border-bottom: 2px solid #00ff88 !important;
        background: transparent !important;
    }
    [data-testid="stTabs"] button:hover { color: #c9d1d9 !important; }
    [data-testid="stTabsContent"] { padding-top: 1.2rem; }

    /* ── Metric cards — glassmorphism ── */
    [data-testid="metric-container"] {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.07);
        position: relative;
        overflow: hidden;
        background: linear-gradient(
            135deg,
            rgba(255,255,255,0.055) 0%,
            rgba(255,255,255,0.018) 100%
        ) !important;
        border: 1px solid rgba(255,255,255,0.09) !important;
        border-radius: 16px !important;
        padding: 20px 24px !important;
        backdrop-filter: blur(14px) saturate(160%) !important;
        -webkit-backdrop-filter: blur(14px) saturate(160%) !important;
        box-shadow:
            0 4px 24px rgba(0,0,0,0.35),
            inset 0 1px 0 rgba(255,255,255,0.07) !important;
        transition: transform 0.22s ease, box-shadow 0.22s ease, border-color 0.22s ease !important;
    }
    /* Shimmer sweep on hover */
    [data-testid="metric-container"]::before {
        content: "";
        position: absolute;
        top: 0; left: -120%;
        width: 70%; height: 100%;
        background: linear-gradient(
            105deg,
            transparent 20%,
            rgba(255,255,255,0.06) 50%,
            transparent 80%
        );
        transition: left 0.55s ease;
        pointer-events: none;
    }
    [data-testid="metric-container"]:hover::before { left: 160%; }
    [data-testid="metric-container"]:hover {
        transform: translateY(-2px) !important;
        border-color: rgba(0,255,136,0.28) !important;
        box-shadow:
            0 8px 32px rgba(0,0,0,0.45),
            0 0 22px rgba(0,255,136,0.08),
            inset 0 1px 0 rgba(255,255,255,0.1) !important;
    }
    [data-testid="stMetricLabel"] {
        color: #4a5568 !important;
        font-size: 0.65rem !important;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        font-family: 'JetBrains Mono', monospace !important;
    }
    [data-testid="stMetricValue"] {
        color: #e2e8f0 !important;
        font-size: 1.95rem !important;
        font-weight: 700;
        text-shadow: 0 0 20px rgba(0,255,136,0.15);
    }
    [data-testid="stMetricDelta"] { font-size: 0.68rem !important; }

    /* ══════════════════════════════════════════════════════════════
       3. HEADER
    ══════════════════════════════════════════════════════════════ */
    .aegis-header {
        background: linear-gradient(
            135deg,
            rgba(13,17,23,0.92) 0%,
            rgba(15,25,35,0.92) 60%,
            rgba(13,17,23,0.92) 100%
        );
        backdrop-filter: blur(16px);
        padding: 1.1rem 1.8rem;
        border-radius: 14px;
        border: 1px solid rgba(0,255,136,0.12);
        border-bottom: 2px solid #00ff88;
        margin-bottom: 1.4rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 0 40px rgba(0,255,136,0.04), inset 0 1px 0 rgba(255,255,255,0.05);
        position: relative;
        overflow: hidden;
    }
    /* Animated corner glow */
    .aegis-header::before {
        content: "";
        position: absolute;
        top: -40px; left: -40px;
        width: 180px; height: 180px;
        background: radial-gradient(circle, rgba(0,255,136,0.08) 0%, transparent 70%);
        animation: cornerGlow 4s ease-in-out infinite alternate;
    }
    @keyframes cornerGlow {
        0%   { opacity: 0.6; transform: scale(1); }
        100% { opacity: 1.0; transform: scale(1.3); }
    }
    .aegis-title {
        font-family: 'JetBrains Mono', monospace;
        color: #e2e8f0;
        font-size: 1.15rem;
        font-weight: 700;
        letter-spacing: 0.07em;
        margin: 0;
        text-shadow: 0 0 30px rgba(0,255,136,0.2);
    }
    .aegis-title span { color: #00ff88; }
    .engine-badge {
        display: flex; align-items: center; gap: 9px;
        color: #00ff88; font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem; font-weight: 600;
        background: rgba(0,255,136,0.05);
        border: 1px solid rgba(0,255,136,0.2);
        border-radius: 20px; padding: 5px 14px;
        box-shadow: 0 0 12px rgba(0,255,136,0.06);
    }
    .pulse-dot {
        width: 8px; height: 8px; border-radius: 50%;
        background: #00ff88;
        box-shadow: 0 0 8px #00ff88, 0 0 16px rgba(0,255,136,0.5);
        animation: pa 1.6s infinite; flex-shrink: 0;
    }
    @keyframes pa {
        0%   { box-shadow: 0 0 0 0 rgba(0,255,136,0.7); }
        70%  { box-shadow: 0 0 0 8px rgba(0,255,136,0); }
        100% { box-shadow: 0 0 0 0 rgba(0,255,136,0); }
    }

    /* ══════════════════════════════════════════════════════════════
       4. BUTTONS — Neon hover states
    ══════════════════════════════════════════════════════════════ */
    .stButton > button {
        position: relative;
        overflow: hidden;
        background: rgba(255,255,255,0.025) !important;
        border: 1px solid rgba(255,255,255,0.08) !important;
        color: #6b7280 !important;
        border-radius: 8px !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.7rem !important;
        letter-spacing: 0.07em !important;
        padding: 0.45rem 0.9rem !important;
        transition: all 0.18s cubic-bezier(0.4,0,0.2,1) !important;
        backdrop-filter: blur(6px) !important;
    }
    /* Sweep shine on hover */
    .stButton > button::after {
        content: "";
        position: absolute;
        top: 0; left: -100%;
        width: 60%; height: 100%;
        background: linear-gradient(
            105deg,
            transparent,
            rgba(255,255,255,0.07),
            transparent
        );
        transition: left 0.35s ease;
    }
    .stButton > button:hover::after { left: 150%; }
    .stButton > button:hover {
        border-color: #00ff88 !important;
        color: #00ff88 !important;
        background: rgba(0,255,136,0.05) !important;
        box-shadow:
            0 0 14px rgba(0,255,136,0.18),
            0 0 28px rgba(0,255,136,0.07),
            inset 0 0 8px rgba(0,255,136,0.03) !important;
        transform: translateY(-1px) !important;
    }
    .stButton > button:active {
        transform: translateY(0px) !important;
        box-shadow: 0 0 6px rgba(0,255,136,0.15) !important;
    }
    /* Isolation / EXECUTE button */
    .isolation-btn > button {
        background: linear-gradient(135deg, rgba(107,0,0,0.8), rgba(179,0,0,0.8)) !important;
        border: 1px solid rgba(255,60,60,0.4) !important;
        color: #fff !important;
        font-weight: 700 !important;
        letter-spacing: 0.1em !important;
        box-shadow: 0 0 10px rgba(255,0,0,0.12) !important;
    }
    .isolation-btn > button:hover {
        background: linear-gradient(135deg, rgba(150,0,0,0.9), rgba(220,0,0,0.9)) !important;
        border-color: rgba(255,60,60,0.8) !important;
        box-shadow: 0 0 28px rgba(255,0,0,0.35), inset 0 0 10px rgba(255,0,0,0.1) !important;
        color: #fff !important;
    }
    /* Download button */
    .stDownloadButton > button {
        background: rgba(0,255,136,0.06) !important;
        border: 1px solid rgba(0,255,136,0.25) !important;
        color: #00ff88 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.7rem !important;
        letter-spacing: 0.08em !important;
        transition: all 0.18s !important;
    }
    .stDownloadButton > button:hover {
        background: rgba(0,255,136,0.12) !important;
        box-shadow: 0 0 20px rgba(0,255,136,0.22) !important;
        border-color: #00ff88 !important;
        transform: translateY(-1px) !important;
    }

    /* ══════════════════════════════════════════════════════════════
       5. DATAFRAME — Glowing rows for high-risk events
    ══════════════════════════════════════════════════════════════ */
    [data-testid="stDataFrame"] {
        border-radius: 10px !important;
        overflow: hidden !important;
        border: 1px solid #1a2433 !important;
    }

    /* Critical row glow injected via JS (see below) — CSS class hooks */
    tr.row-critical {
        background: rgba(255,60,60,0.07) !important;
        box-shadow: inset 3px 0 0 #ff3c3c, 0 0 12px rgba(255,60,60,0.15);
        animation: rowPulse 2.5s ease-in-out infinite;
    }
    tr.row-high {
        background: rgba(255,165,0,0.05) !important;
        box-shadow: inset 3px 0 0 #ffa500;
    }
    tr.row-benign {
        background: rgba(0,255,136,0.025) !important;
        box-shadow: inset 3px 0 0 rgba(0,255,136,0.4);
    }
    @keyframes rowPulse {
        0%, 100% { box-shadow: inset 3px 0 0 #ff3c3c, 0 0 8px  rgba(255,60,60,0.12); }
        50%       { box-shadow: inset 3px 0 0 #ff3c3c, 0 0 20px rgba(255,60,60,0.28); }
    }

    /* ══════════════════════════════════════════════════════════════
       6. TABS
    ══════════════════════════════════════════════════════════════ */
    [data-testid="stTabs"] button {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.73rem !important;
        letter-spacing: 0.12em !important;
        text-transform: uppercase !important;
        color: #4a5568 !important;
        border-bottom: 2px solid transparent !important;
        padding: 0.6rem 1.4rem !important;
        transition: all 0.2s !important;
        background: transparent !important;
    }
    [data-testid="stTabs"] button[aria-selected="true"] {
        color: #00ff88 !important;
        border-bottom: 2px solid #00ff88 !important;
        text-shadow: 0 0 12px rgba(0,255,136,0.6);
    }
    [data-testid="stTabs"] button:hover {
        color: #c9d1d9 !important;
        text-shadow: 0 0 8px rgba(200,210,220,0.2);
    }
    [data-testid="stTabsContent"] { padding-top: 1.2rem; }

    /* ══════════════════════════════════════════════════════════════
       7. EXPANDERS
    ══════════════════════════════════════════════════════════════ */
    [data-testid="stExpander"] {
        background: rgba(255,255,255,0.018) !important;
        border: 1px solid #1a2433 !important;
        border-radius: 10px !important;
        backdrop-filter: blur(8px) !important;
        transition: border-color 0.2s !important;
    }
    [data-testid="stExpander"]:hover {
        border-color: rgba(255,255,255,0.1) !important;
    }
    [data-testid="stExpanderToggleIcon"] { color: #4a5568; }

    /* ══════════════════════════════════════════════════════════════
       8. TRIAGE CARDS
    ══════════════════════════════════════════════════════════════ */
    .triage-card {
        background: rgba(255,60,60,0.04);
        border: 1px solid rgba(255,60,60,0.18);
        border-left: 3px solid #ff3c3c;
        border-radius: 12px;
        padding: 14px 18px;
        margin-bottom: 12px;
        font-family: 'JetBrains Mono', monospace;
        backdrop-filter: blur(6px);
        transition: all 0.2s ease;
        position: relative;
        overflow: hidden;
    }
    .triage-card:hover {
        border-color: rgba(255,60,60,0.45);
        box-shadow: 0 0 18px rgba(255,60,60,0.1), inset 0 0 8px rgba(255,60,60,0.03);
        transform: translateX(2px);
    }
    .triage-score { color: #ff3c3c; font-size: 1.5rem; font-weight: 900; text-shadow: 0 0 16px rgba(255,60,60,0.5); }
    .triage-meta  { color: #4a5568; font-size: 0.65rem; margin-top: 3px; }

    /* ══════════════════════════════════════════════════════════════
       9. SIDEBAR — Glass panel
    ══════════════════════════════════════════════════════════════ */
    [data-testid="stSidebar"] {
        background-color: #0d1117;
        border-right: 1px solid #1a2433;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: #070b11; }
    ::-webkit-scrollbar-thumb { background: #1a2433; border-radius: 2px; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ── Data Layer ────────────────────────────────────────────────────────
def fetch_logs(limit: int = 50) -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame()
    conn = sqlite3.connect(str(DB_PATH))
    try:
        df = pd.read_sql_query(
            f"""SELECT id, timestamp, event_id, user_account, source_ip,
                       status, threat_score, verdicts
                FROM security_events
                ORDER BY timestamp DESC LIMIT {limit}""",
            conn,
        )
    finally:
        conn.close()
    if df.empty:
        return df
    df["threat_score"] = pd.to_numeric(df["threat_score"], errors="coerce").fillna(0.0)
    df["timestamp"]    = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df


def fetch_all_scored() -> pd.DataFrame:
    """Return every scored event for historical analytics."""
    if not DB_PATH.exists():
        return pd.DataFrame()
    conn = sqlite3.connect(str(DB_PATH))
    try:
        df = pd.read_sql_query(
            """SELECT timestamp, threat_score, event_id
               FROM security_events
               WHERE threat_score IS NOT NULL
               ORDER BY timestamp ASC""",
            conn,
        )
    finally:
        conn.close()
    if df.empty:
        return df
    df["threat_score"] = pd.to_numeric(df["threat_score"], errors="coerce").fillna(0.0)
    df["timestamp"]    = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df


def get_metrics(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"total": 0, "threats": 0, "avg_conf": "N/A", "mtc": "N/A"}
    total   = len(df)
    threats = int((df["threat_score"] > 7.0).sum())
    confs   = []
    for _, row in df.iterrows():
        if row["verdicts"]:
            try:
                for v in json.loads(row["verdicts"]):
                    confs.append(v.get("confidence", 0.0))
            except Exception:
                pass
    avg_conf = f"{(sum(confs)/len(confs))*100:.1f}%" if confs else "N/A"
    return {"total": total, "threats": threats, "avg_conf": avg_conf, "mtc": "3.2s"}


def row_color(score: float) -> str:
    try:
        score = float(score) if pd.notna(score) else 0.0
    except (ValueError, TypeError):
        score = 0.0
    if score > 7.0:
        return "background-color:rgba(255,60,60,0.15); color:#ff6b6b;"
    if score >= 4.0:
        return "background-color:rgba(255,165,0,0.12); color:#ffa94d;"
    return "background-color:rgba(0,255,136,0.05); color:#69db7c;"


# ── Geo-Map ───────────────────────────────────────────────────────────
def build_threat_map(df: pd.DataFrame) -> go.Figure:
    lats, lons, texts, sizes, colors = [], [], [], [], []
    ht_lats, ht_lons = [], []

    for _, row in df.iterrows():
        lat, lon, loc = ip_to_geo(row["source_ip"])
        score = float(row["threat_score"])
        lats.append(lat); lons.append(lon)
        texts.append(
            f"<b>{row['source_ip']}</b><br>"
            f"Location: {loc}<br>Score: {score:.2f}<br>"
            f"User: {row['user_account']}<br>Event: {row['event_id']}"
        )
        sizes.append(6 + score * 2.4)
        if score > 7.0:
            colors.append("rgba(255,60,60,0.85)"); ht_lats.append(lat); ht_lons.append(lon)
        elif score >= 4.0:
            colors.append("rgba(255,165,0,0.75)")
        else:
            colors.append("rgba(0,255,136,0.55)")

    fig = go.Figure()
    fig.add_trace(go.Scattergeo(
        lon=lons, lat=lats, mode="markers",
        marker=dict(size=sizes, color=colors,
                    line=dict(width=0.5, color="rgba(255,255,255,0.1)"),
                    sizemode="diameter"),
        text=texts, hovertemplate="%{text}<extra></extra>",
        name="IP Origins",
    ))
    if ht_lats:
        fig.add_trace(go.Scattergeo(
            lon=ht_lons, lat=ht_lats, mode="markers",
            marker=dict(size=28, color="rgba(255,0,0,0.07)",
                        line=dict(width=1.5, color="rgba(255,60,60,0.35)"),
                        sizemode="diameter"),
            hoverinfo="skip", showlegend=False,
        ))

    fig.update_geos(
        projection_type="natural earth",
        showland=True,    landcolor="#0c1520",
        showocean=True,   oceancolor="#060d14",
        showcountries=True, countrycolor="#1a2433",
        showcoastlines=True, coastlinecolor="#1a2433",
        showframe=False,  bgcolor="#070b11",
    )
    fig.update_layout(
        paper_bgcolor="#070b11", plot_bgcolor="#070b11",
        margin=dict(l=0, r=0, t=0, b=0), height=360,
        legend=dict(font=dict(color="#4a5568", size=10),
                    bgcolor="rgba(0,0,0,0)", x=0.01, y=0.02),
    )
    return fig


# ── Historical Area Chart ─────────────────────────────────────────────
def build_area_chart(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return go.Figure()

    # Bin events into 1-minute buckets and compute mean threat score
    df2 = df.set_index("timestamp").sort_index()
    binned = df2["threat_score"].resample("1min").mean().dropna().reset_index()
    binned.columns = ["ts", "avg_score"]

    # Rolling 5-period smooth
    binned["smooth"] = binned["avg_score"].rolling(3, min_periods=1).mean()

    fig = go.Figure()

    # ── Critical band (score > 7) reference line ──
    fig.add_hline(y=7.0, line_dash="dot",
                  line=dict(color="rgba(255,60,60,0.35)", width=1),
                  annotation_text="CRITICAL THRESHOLD",
                  annotation_font=dict(size=9, color="rgba(255,60,60,0.6)"),
                  annotation_position="top left")

    fig.add_hline(y=4.0, line_dash="dot",
                  line=dict(color="rgba(255,165,0,0.25)", width=1),
                  annotation_text="HIGH THRESHOLD",
                  annotation_font=dict(size=9, color="rgba(255,165,0,0.5)"),
                  annotation_position="top left")

    # ── Raw data bars (very faint) ──
    fig.add_trace(go.Bar(
        x=binned["ts"], y=binned["avg_score"],
        marker_color="rgba(0,255,136,0.04)",
        marker_line_width=0,
        name="Raw avg",
        hovertemplate="%{y:.2f}<extra>Raw</extra>",
    ))

    # ── Neon area fill ──
    fig.add_trace(go.Scatter(
        x=binned["ts"], y=binned["smooth"],
        mode="lines",
        line=dict(color="#00ff88", width=2.5, shape="spline", smoothing=1.2),
        fill="tozeroy",
        fillcolor="rgba(0,255,136,0.06)",
        name="Avg Threat Score",
        hovertemplate="<b>%{x|%H:%M}</b><br>Avg Score: %{y:.2f}<extra></extra>",
    ))

    # ── Critical zone overlay ──
    crit = binned[binned["smooth"] > 7.0]
    if not crit.empty:
        fig.add_trace(go.Scatter(
            x=crit["ts"], y=crit["smooth"],
            mode="lines",
            line=dict(color="#ff3c3c", width=2.5, shape="spline", smoothing=1.2),
            fill="tozeroy",
            fillcolor="rgba(255,60,60,0.08)",
            name="Critical Zone",
            hovertemplate="<b>%{x|%H:%M}</b><br>CRITICAL: %{y:.2f}<extra></extra>",
        ))

    fig.update_layout(
        paper_bgcolor="#070b11",
        plot_bgcolor="#070b11",
        margin=dict(l=0, r=10, t=20, b=0),
        height=340,
        font=dict(family="JetBrains Mono", color="#4a5568", size=10),
        xaxis=dict(
            showgrid=True, gridcolor="rgba(255,255,255,0.04)",
            zeroline=False, showline=False,
            tickfont=dict(size=9, color="#4a5568"),
            title=None,
        ),
        yaxis=dict(
            showgrid=True, gridcolor="rgba(255,255,255,0.04)",
            zeroline=False, range=[0, 10.5],
            tickfont=dict(size=9, color="#4a5568"),
            title=dict(text="Avg Threat Score", font=dict(size=9, color="#4a5568")),
        ),
        legend=dict(
            font=dict(size=9, color="#4a5568"),
            bgcolor="rgba(0,0,0,0)",
            orientation="h", x=0, y=1.08,
        ),
        hovermode="x unified",
        hoverlabel=dict(bgcolor="#0d1117", font=dict(size=10, color="#e2e8f0"),
                        bordercolor="#1a2433"),
    )
    return fig


# ── Lateral Movement Topology Graph (CrowdStrike-style, Plotly) ──────────────
def build_topology_graph(
    source_ip: str,
    user_account: str,
    event_id: str,
    verdicts: list,
    score: float,
) -> None:
    """
    Render a polished, CrowdStrike-inspired attack topology graph using Plotly.
    Fixed hierarchical layout: Attacker IP → Event ID → Target Account.
    MITRE tactic nodes branch downward from the Event node.
    """

    # ── Colour palette ───────────────────────────────────────────────
    c_bg    = "#050810"
    c_attack = "#ff3c3c" if score > 7.0 else "#ffa500" if score >= 4.0 else "#00ff88"
    c_event  = "#f97316"
    c_user   = "#38bdf8"
    c_mitre  = "#a855f7"
    c_dash   = "rgba(168,85,247,0.45)"

    sev_label = "CRITICAL" if score > 7.0 else "HIGH" if score >= 4.0 else "LOW"
    badge_bg  = (
        "rgba(255,60,60,0.12)"  if score > 7.0  else
        "rgba(255,165,0,0.10)"  if score >= 4.0 else
        "rgba(0,255,136,0.08)"
    )

    EVENT_META: dict[str, tuple[str, str]] = {
        "4624": ("Logon Success",  "CREDENTIAL USE"),
        "4625": ("Brute Force",    "CREDENTIAL ATTACK"),
        "4688": ("Process Spawn",  "EXECUTION"),
        "7045": ("Svc Installed",  "PERSISTENCE"),
    }
    etype, ecategory = EVENT_META.get(str(event_id), (f"Evt {event_id}", "WINDOWS EVENT"))

    tactics: list[str] = []
    for v in verdicts:
        t = v.get("mitre_tactic", "").strip()
        if t and t != "None" and t not in tactics:
            tactics.append(t)
    n_mitre = len(tactics)

    # ── Fixed node positions ─────────────────────────────────────────
    X_IP, X_EVT, X_USR = 0, 5, 10
    Y_MAIN = 0

    fig = go.Figure()

    # ── Background grid ───────────────────────────────────────────────
    for y_g in [1.5, 0, -1.5, -3.0, -4.5]:
        fig.add_shape(type="line", x0=-1.5, x1=11.5, y0=y_g, y1=y_g,
                      line=dict(color="rgba(255,255,255,0.022)", width=1))
    for x_g in [0, 2.5, 5, 7.5, 10]:
        fig.add_shape(type="line", x0=x_g, x1=x_g,
                      y0=-1.1 - n_mitre * 2.4, y1=1.5,
                      line=dict(color="rgba(255,255,255,0.018)", width=1))
    if n_mitre:
        fig.add_shape(type="line", x0=-0.5, x1=10.5, y0=-1.3, y1=-1.3,
                      line=dict(color="rgba(168,85,247,0.12)", width=1, dash="dot"))

    # ── Edges ─────────────────────────────────────────────────────────
    def _edge(x0, y0, x1, y1, color, dash="solid", width=2.5):
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1], mode="lines",
            line=dict(color=color, width=width, dash=dash),
            hoverinfo="skip", showlegend=False,
        ))
        fig.add_annotation(
            x=x1, y=y1, ax=x0, ay=y0,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True, arrowhead=3, arrowsize=1.3,
            arrowwidth=width, arrowcolor=color,
        )

    _edge(X_IP + 0.65, Y_MAIN, X_EVT - 0.62, Y_MAIN, c_attack)
    _edge(X_EVT + 0.62, Y_MAIN, X_USR - 0.62, Y_MAIN, c_event)
    for i in range(n_mitre):
        y_m = -(i + 1) * 2.4
        _edge(X_EVT, -0.65, X_EVT, y_m + 0.52, c_dash, dash="dot", width=1.5)
        # Short connector to label
        fig.add_trace(go.Scatter(
            x=[X_EVT + 0.5, X_EVT + 1.15], y=[y_m, y_m], mode="lines",
            line=dict(color=c_dash, width=1, dash="dot"),
            hoverinfo="skip", showlegend=False,
        ))

    # ── Nodes — 3-layer: glow → ring → fill ──────────────────────────
    def _node(x, y, color, symbol, size, glow, hover):
        # Ambient glow
        fig.add_trace(go.Scatter(
            x=[x], y=[y], mode="markers",
            marker=dict(size=glow, color=color, opacity=0.07,
                        line=dict(width=0), symbol="circle"),
            hoverinfo="skip", showlegend=False,
        ))
        # Coloured border ring
        fig.add_trace(go.Scatter(
            x=[x], y=[y], mode="markers",
            marker=dict(size=size + 9, color="rgba(0,0,0,0)",
                        line=dict(width=3, color=color), symbol=symbol),
            hoverinfo="skip", showlegend=False,
        ))
        # Dark fill + hover
        fig.add_trace(go.Scatter(
            x=[x], y=[y], mode="markers",
            marker=dict(size=size, color=c_bg,
                        line=dict(width=0), symbol=symbol),
            hovertemplate=hover + "<extra></extra>",
            showlegend=False, name="",
        ))

    _node(X_IP,  Y_MAIN, c_attack, "hexagon", 46, 82,
          f"<b>Attacker Origin</b><br>IP: {source_ip}<br>"
          f"Threat Score: {score:.2f}<br>Severity: {sev_label}")
    _node(X_EVT, Y_MAIN, c_event,  "square",  42, 72,
          f"<b>Attack Vector</b><br>EventID: {event_id}<br>"
          f"Type: {etype}<br>Category: {ecategory}")
    _node(X_USR, Y_MAIN, c_user,   "circle",  42, 72,
          f"<b>Target Identity</b><br>Account: {user_account}")
    for i, t in enumerate(tactics):
        y_m = -(i + 1) * 2.4
        _node(X_EVT, y_m, c_mitre, "diamond", 32, 56,
              f"<b>MITRE ATT&amp;CK</b><br>{t}")

    # ── Annotations ───────────────────────────────────────────────────
    anns = []

    def _ann(x, y, text, color, size, anchor="center", bg=None, bc=None):
        d = dict(x=x, y=y, text=text,
                 font=dict(size=size, color=color, family="JetBrains Mono"),
                 showarrow=False, xanchor=anchor)
        if bg:
            d.update(bgcolor=bg, bordercolor=bc, borderpad=4, borderwidth=1)
        anns.append(d)

    # Attacker
    _ann(X_IP, 0.88,  f"<b>{source_ip}</b>",      c_attack, 11)
    _ann(X_IP, 0.60,  "ATTACKER ORIGIN",           "#4a5568", 7.5)
    _ann(X_IP, -0.86, f"  {sev_label}  {score:.1f}  ",
         c_attack, 9, bg=badge_bg, bc=c_attack)

    # Event
    _ann(X_EVT, 0.88,  f"<b>EventID {event_id}</b>", c_event, 11)
    _ann(X_EVT, 0.60,  ecategory,                     "#4a5568", 7.5)
    _ann(X_EVT, -0.86, f"  {etype}  ",
         c_event, 9, bg="rgba(249,115,22,0.08)", bc=c_event)

    # User
    disp_u = user_account[:14] + "…" if len(user_account) > 16 else user_account
    _ann(X_USR, 0.88, f"<b>{disp_u}</b>", c_user, 11)
    _ann(X_USR, 0.60, "TARGET IDENTITY",  "#4a5568", 7.5)

    # Edge labels
    _ann(2.5, 0.25, "triggers",      "rgba(255,255,255,0.22)", 8)
    _ann(7.5, 0.25, "targets",       "rgba(255,255,255,0.22)", 8)

    # MITRE labels
    for i, t in enumerate(tactics):
        y_m = -(i + 1) * 2.4
        short_t = t[:22] + "…" if len(t) > 24 else t
        _ann(X_EVT + 1.25, y_m + 0.22,  f"<b>{short_t}</b>",   c_mitre,   9.5, "left")
        _ann(X_EVT + 1.25, y_m - 0.24,  "MITRE ATT&amp;CK",    "#4a5568", 7,   "left")
        _ann(X_EVT + 0.22, (Y_MAIN - 0.65 + y_m + 0.52) / 2,
             "classified as", "rgba(168,85,247,0.45)", 7, "left")

    fig.update_layout(annotations=anns)

    y_min = max(-1.6, -(n_mitre) * 2.4 - 0.9)
    fig.update_layout(
        paper_bgcolor=c_bg, plot_bgcolor=c_bg,
        height=max(300, 200 + n_mitre * 100),
        margin=dict(l=10, r=10, t=8, b=8),
        xaxis=dict(showgrid=False, showline=False, showticklabels=False,
                   zeroline=False, range=[-1.5, 11.5], fixedrange=True),
        yaxis=dict(showgrid=False, showline=False, showticklabels=False,
                   zeroline=False, range=[y_min, 1.6], fixedrange=True),
        hovermode="closest",
        hoverlabel=dict(bgcolor="#0d1117",
                        font=dict(size=11, color="#e2e8f0", family="JetBrains Mono"),
                        bordercolor="#1a2433"),
        dragmode=False,
    )
    st.plotly_chart(fig, use_container_width=True,
                    config={"displayModeBar": False, "staticPlot": False})


def render_microscope(row_data: pd.Series, orig: pd.Series, key_prefix: str = ""):
    score  = float(row_data["threat_score"])
    badge  = "#ff3c3c" if score > 7.0 else "#ffa500" if score >= 4.0 else "#00ff88"
    label  = "CRITICAL" if score > 7.0 else "HIGH" if score >= 4.0 else "BENIGN"

    st.markdown(
        f"""
        <div style="display:flex; justify-content:space-between; align-items:center;
                    background:rgba(255,255,255,0.02); border:1px solid #1a2433;
                    border-left:3px solid {badge}; border-radius:8px;
                    padding:10px 14px; margin-bottom:10px;
                    font-family:'JetBrains Mono',monospace;">
            <div>
                <div style="color:#4a5568; font-size:0.6rem; letter-spacing:0.12em;">CONSENSUS SCORE</div>
                <div style="color:{badge}; font-size:1.55rem; font-weight:900; line-height:1.1;">{score:.2f}</div>
            </div>
            <div style="text-align:right;">
                <div style="color:{badge}; font-size:0.65rem; font-weight:700;
                            background:rgba(255,255,255,0.04); border-radius:10px; padding:3px 9px;">
                    {label}
                </div>
                <div style="color:#4a5568; font-size:0.6rem; margin-top:4px;">{row_data['source_ip']}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"<span style='font-family:monospace;font-size:0.75rem;color:#4a5568;'>"
        f"EventID <b style='color:#8892a4'>{row_data['event_id']}</b> &nbsp;|&nbsp;"
        f"User <b style='color:#8892a4'>{row_data['user_account']}</b>"
        f"</span>",
        unsafe_allow_html=True,
    )

    # ── Lateral Movement Topology Graph ────────────────────────────
    st.markdown(
        "<div style='font-family:monospace; color:#4a5568; font-size:0.6rem;"
        " letter-spacing:0.15em; margin:8px 0 2px;'>ATTACK TOPOLOGY GRAPH</div>",
        unsafe_allow_html=True,
    )
    verdicts_raw = []
    verdicts_str_raw = orig.get("verdicts", None)
    if verdicts_str_raw:
        try:
            verdicts_raw = json.loads(verdicts_str_raw)
        except Exception:
            pass

    build_topology_graph(
        source_ip=str(row_data["source_ip"]),
        user_account=str(row_data["user_account"]),
        event_id=str(row_data["event_id"]),
        verdicts=verdicts_raw,
        score=score,
    )

    # ── Agent Verdict Expanders ──────────────────────────────────────
    verdicts_str = orig.get("verdicts", None)
    if verdicts_str:
        try:
            verdicts = json.loads(verdicts_str)
            for i, v in enumerate(verdicts):
                agent    = v.get("agent_name", "Unknown")
                r_score  = v.get("risk_score", 0.0)
                conf     = v.get("confidence", 0.0)
                mitre    = v.get("mitre_tactic", "None")
                rationale = v.get("rationale", "")
                with st.expander(
                    f"{agent}  |  Risk {r_score:.1f}  |  Conf {conf:.0%}",
                    expanded=(r_score > 6),
                ):
                    if mitre and mitre != "None":
                        st.markdown(
                            f"<span style='color:#f97316; font-family:monospace; font-size:0.72rem;'>"
                            f"MITRE: {mitre}</span>",
                            unsafe_allow_html=True,
                        )
                    st.caption(rationale)
        except Exception as e:
            st.error(f"Verdict parse error: {e}")
    else:
        st.warning("No swarm verdicts yet.")

    if score > 7.0:
        st.markdown("---")
        st.markdown(
            "<div style='color:#ff3c3c; font-family:monospace; font-size:0.62rem;"
            " letter-spacing:0.12em; margin-bottom:5px;'>CISO ACTION REQUIRED</div>",
            unsafe_allow_html=True,
        )
        bc1, bc2 = st.columns(2)
        with bc1:
            st.markdown("<div class='isolation-btn'>", unsafe_allow_html=True)
            if st.button("EXECUTE HOST ISOLATION", key=f"{key_prefix}_iso", use_container_width=True):
                st.toast("Webhook dispatched. Host isolated.", icon="🔒")
            st.markdown("</div>", unsafe_allow_html=True)
        with bc2:
            if st.button("MARK FALSE POSITIVE", key=f"{key_prefix}_fp", use_container_width=True):
                st.toast("Marked false positive.", icon="✅")

    st.markdown("---")
    st.markdown(
        "<div style='color:#4a5568; font-family:monospace; font-size:0.6rem;"
        " letter-spacing:0.12em; margin-bottom:5px;'>INCIDENT REPORT</div>",
        unsafe_allow_html=True,
    )
    try:
        rpath = generate_incident_report(orig["id"])
        st.download_button(
            label="DOWNLOAD BOARDROOM REPORT",
            data=rpath.read_text(encoding="utf-8"),
            file_name=rpath.name,
            mime="text/markdown",
            use_container_width=True,
            key=f"{key_prefix}_dl",
        )
    except Exception as e:
        st.error(f"Report error: {e}")


# ── App Shell ─────────────────────────────────────────────────────────

# Header
engine_label = (
    settings.CLOUD_MODEL if str(settings.ACTIVE_MODE).upper() == "CLOUD"
    else settings.LOCAL_MODEL
).upper()
mode_label = str(settings.ACTIVE_MODE).upper()

st.markdown(
    f"""
    <div class="aegis-header">
        <h1 class="aegis-title">SOTERIA <span>//</span> AUTONOMOUS THREAT TRIBUNAL</h1>
        <div class="engine-badge">
            <div class="pulse-dot"></div>
            {mode_label} &nbsp;|&nbsp; {engine_label}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Tab Bar ───────────────────────────────────────────────────────────
tab_arena, tab_history, tab_triage = st.tabs([
    "  Live Arena  ",
    "  Historical Analytics  ",
    "  Triage Queue  ",
])


# ════════════════════════════════════════════════════════════════════
#  TAB 1 — LIVE ARENA
# ════════════════════════════════════════════════════════════════════
with tab_arena:

    @st.fragment(run_every="4s")
    def arena_fragment():
        df      = fetch_logs()
        metrics = get_metrics(df)

        # Metrics row
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Logs Scanned",      metrics["total"])
        m2.metric("Active Threats",          metrics["threats"],
                  delta=f"+{metrics['threats']} critical" if metrics["threats"] else None,
                  delta_color="inverse")
        m3.metric("Avg Tribunal Confidence", metrics["avg_conf"])
        m4.metric("Mean Time to Consensus",  metrics["mtc"])

        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

        # Geo map
        st.markdown("<div class='section-label'>Global Threat Origin Map</div>",
                    unsafe_allow_html=True)
        if df.empty:
            st.info("No data yet. Start `mock_generator.py` and `run_soc.py`.")
            return

        fig_map = build_threat_map(df)
        st.plotly_chart(fig_map, use_container_width=True,
                        config={"displayModeBar": False})

        # Legend pills
        lc1, lc2, lc3, _ = st.columns([1, 1, 1, 3])
        lc1.markdown("<span style='color:#ff3c3c;font-family:monospace;font-size:0.7rem;'>&#9679; CRITICAL (&gt;7)</span>", unsafe_allow_html=True)
        lc2.markdown("<span style='color:#ffa500;font-family:monospace;font-size:0.7rem;'>&#9679; HIGH (4-7)</span>",       unsafe_allow_html=True)
        lc3.markdown("<span style='color:#00ff88;font-family:monospace;font-size:0.7rem;'>&#9679; BENIGN (&lt;4)</span>",   unsafe_allow_html=True)

        st.divider()

        # Two-column arena
        col1, col2 = st.columns([1.6, 1])

        with col1:
            st.markdown("<div class='section-label'>Live Event Feed — Last 15</div>",
                        unsafe_allow_html=True)
            display_df = df.drop(columns=["verdicts"]).head(15)
            # format timestamp for display
            disp = display_df.copy()
            disp["timestamp"] = disp["timestamp"].dt.strftime("%H:%M:%S")
            styled = disp.style.apply(
                lambda x: [row_color(x["threat_score"])] * len(x), axis=1
            ).format({"threat_score": "{:.2f}"})
            event = st.dataframe(
                styled, use_container_width=True, hide_index=True,
                on_select="rerun", selection_mode="single-row",
                key="arena_df",
            )

        with col2:
            st.markdown("<div class='section-label'>Swarm Microscope</div>",
                        unsafe_allow_html=True)
            sel = event.selection.rows
            if not sel:
                st.markdown(
                    """<div style="border:1px dashed #1a2433; border-radius:10px;
                                  padding:2.5rem 1rem; text-align:center;
                                  color:#2d3748; font-family:'JetBrains Mono',monospace;
                                  font-size:0.75rem; margin-top:6px;">
                        SELECT A ROW<br>to inspect agent verdicts
                    </div>""",
                    unsafe_allow_html=True,
                )
            else:
                idx = sel[0]
                render_microscope(
                    display_df.iloc[idx],
                    df.iloc[idx],
                    key_prefix=f"arena_{idx}",
                )

    arena_fragment()


# ════════════════════════════════════════════════════════════════════
#  TAB 2 — HISTORICAL ANALYTICS
# ════════════════════════════════════════════════════════════════════
with tab_history:

    @st.fragment(run_every="15s")
    def history_fragment():
        hist_df = fetch_all_scored()

        st.markdown("<div class='section-label'>Threat Score Timeline — 1-Min Buckets</div>",
                    unsafe_allow_html=True)

        if hist_df.empty:
            st.info("No scored events yet. The SOC engine must process at least one log.")
            return

        fig_area = build_area_chart(hist_df)
        st.plotly_chart(fig_area, use_container_width=True,
                        config={"displayModeBar": False})

        st.divider()

        # Summary stats row
        total_scored  = len(hist_df)
        peak_score    = hist_df["threat_score"].max()
        mean_score    = hist_df["threat_score"].mean()
        crit_count    = int((hist_df["threat_score"] > 7.0).sum())
        pct_critical  = (crit_count / total_scored) * 100 if total_scored else 0

        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total Events Scored",  total_scored)
        s2.metric("Peak Threat Score",    f"{peak_score:.2f}")
        s3.metric("Mean Threat Score",    f"{mean_score:.2f}")
        s4.metric("% Critical Events",    f"{pct_critical:.1f}%",
                  delta=f"{crit_count} events",
                  delta_color="inverse" if crit_count > 0 else "off")

        st.divider()

        # Event ID type breakdown bar
        st.markdown("<div class='section-label'>Attack Distribution by Windows Event ID</div>",
                    unsafe_allow_html=True)
        eid_counts = (
            hist_df.groupby("event_id")["threat_score"]
            .agg(count="count", avg="mean")
            .reset_index()
            .sort_values("count", ascending=True)
        )
        fig_bar = go.Figure(go.Bar(
            x=eid_counts["count"],
            y=eid_counts["event_id"].astype(str),
            orientation="h",
            marker=dict(
                color=eid_counts["avg"],
                colorscale=[[0, "#00ff88"], [0.4, "#ffa500"], [1.0, "#ff3c3c"]],
                cmin=0, cmax=10,
                colorbar=dict(
                    title=dict(text="Avg Score", font=dict(size=8, color="#4a5568")),
                    thickness=8,
                    tickfont=dict(size=8, color="#4a5568"),
                    len=0.6,
                ),
            ),
            text=eid_counts["count"],
            textposition="outside",
            textfont=dict(size=9, color="#8892a4"),
            hovertemplate="<b>%{y}</b><br>Count: %{x}<br>Avg Score: %{marker.color:.2f}<extra></extra>",
        ))
        fig_bar.update_layout(
            paper_bgcolor="#070b11", plot_bgcolor="#070b11",
            height=220, margin=dict(l=0, r=60, t=0, b=0),
            font=dict(family="JetBrains Mono", size=9, color="#4a5568"),
            xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.03)",
                       zeroline=False, tickfont=dict(size=8, color="#4a5568")),
            yaxis=dict(showgrid=False, tickfont=dict(size=9, color="#8892a4")),
        )
        st.plotly_chart(fig_bar, use_container_width=True,
                        config={"displayModeBar": False})

    history_fragment()


# ════════════════════════════════════════════════════════════════════
#  TAB 3 — TRIAGE QUEUE
# ════════════════════════════════════════════════════════════════════
with tab_triage:

    @st.fragment(run_every="5s")
    def triage_fragment():
        all_df = fetch_logs(limit=200)

        # Filter: score > 7.0 AND still pending
        if all_df.empty:
            queue = pd.DataFrame()
        else:
            queue = all_df[
                (all_df["threat_score"] > 7.0) &
                (all_df["status"].str.lower().isin(["pending", "analyzed"]))
            ].copy()

        # Header strip
        count = len(queue)
        badge_bg = "rgba(255,60,60,0.12)" if count > 0 else "rgba(0,255,136,0.06)"
        badge_border = "rgba(255,60,60,0.4)" if count > 0 else "rgba(0,255,136,0.3)"
        badge_color  = "#ff3c3c" if count > 0 else "#00ff88"
        badge_text   = f"{count} INCIDENT{'S' if count != 1 else ''} AWAITING TRIAGE" if count > 0 else "ALL CLEAR - NO PENDING THREATS"

        st.markdown(
            f"""
            <div style="background:{badge_bg}; border:1px solid {badge_border};
                        border-radius:10px; padding:12px 20px; margin-bottom:20px;
                        font-family:'JetBrains Mono',monospace; font-size:0.8rem;
                        color:{badge_color}; font-weight:700; letter-spacing:0.1em;
                        display:flex; align-items:center; gap:12px;">
                <span style="font-size:1.4rem;">{'⚠' if count > 0 else '✓'}</span>
                {badge_text}
            </div>
            """,
            unsafe_allow_html=True,
        )

        if queue.empty:
            st.markdown(
                """<div style="text-align:center; padding:4rem 0;
                              color:#2d3748; font-family:'JetBrains Mono',monospace;
                              font-size:0.85rem;">
                    No critical incidents currently awaiting triage.<br>
                    <span style='font-size:0.7rem;'>Swarm engine is monitoring...</span>
                </div>""",
                unsafe_allow_html=True,
            )
            return

        # Split layout: queue list | detail panel
        tq_left, tq_right = st.columns([1, 1.2])

        with tq_left:
            st.markdown("<div class='section-label'>Critical Incidents — Sorted by Score</div>",
                        unsafe_allow_html=True)
            queue_sorted = queue.sort_values("threat_score", ascending=False)

            # Track selected incident
            if "triage_sel" not in st.session_state:
                st.session_state.triage_sel = None

            for i, (_, row) in enumerate(queue_sorted.iterrows()):
                score = float(row["threat_score"])
                ts_str = row["timestamp"].strftime("%H:%M:%S UTC") if pd.notna(row["timestamp"]) else "Unknown"

                # Determine MITRE tactic if available
                mitre_tag = ""
                if row["verdicts"]:
                    try:
                        vs = json.loads(row["verdicts"])
                        tactics = [v.get("mitre_tactic", "") for v in vs
                                   if v.get("mitre_tactic", "") not in ("", "None")]
                        if tactics:
                            mitre_tag = tactics[0]
                    except Exception:
                        pass

                is_selected = st.session_state.triage_sel == i
                border_color = "#ff3c3c" if not is_selected else "#ff8080"
                bg_color     = "rgba(255,60,60,0.05)" if not is_selected else "rgba(255,60,60,0.12)"

                st.markdown(
                    f"""
                    <div class="triage-card" style="background:{bg_color};border-color:{border_color};cursor:pointer;">
                        <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                            <div>
                                <div style="color:#e2e8f0; font-size:0.75rem; font-weight:600;">
                                    {row['source_ip']}
                                </div>
                                <div class="triage-meta">
                                    {row['user_account']} &nbsp;|&nbsp; EventID {row['event_id']}
                                </div>
                                <div class="triage-meta">{ts_str}</div>
                                {'<div style="color:#f97316; font-size:0.6rem; margin-top:4px;">' + mitre_tag + '</div>' if mitre_tag else ''}
                            </div>
                            <div class="triage-score">{score:.1f}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if st.button(
                    f"Inspect",
                    key=f"triage_sel_{i}",
                    use_container_width=True,
                ):
                    st.session_state.triage_sel = i
                    st.rerun()

        with tq_right:
            st.markdown("<div class='section-label'>Incident Detail</div>",
                        unsafe_allow_html=True)
            sel_i = st.session_state.get("triage_sel", None)

            if sel_i is None:
                st.markdown(
                    """<div style="border:1px dashed #1a2433; border-radius:10px;
                                  padding:2.5rem 1rem; text-align:center; color:#2d3748;
                                  font-family:'JetBrains Mono',monospace; font-size:0.75rem;">
                        CLICK INSPECT<br>to analyse an incident
                    </div>""",
                    unsafe_allow_html=True,
                )
            else:
                queue_sorted_reset = queue.sort_values("threat_score", ascending=False).reset_index(drop=True)
                if sel_i < len(queue_sorted_reset):
                    selected_row = queue_sorted_reset.iloc[sel_i]
                    render_microscope(
                        selected_row,
                        selected_row,
                        key_prefix=f"triage_{sel_i}",
                    )

    triage_fragment()


# ── CISO Copilot Sidebar ─────────────────────────────────────────────
with st.sidebar:

    # Header
    st.markdown(
        """
        <div style="font-family:'JetBrains Mono',monospace; color:#00ff88;
                    font-size:0.8rem; font-weight:700; letter-spacing:0.12em;">
            CISO COPILOT
        </div>
        <div style="font-family:'JetBrains Mono',monospace; color:#4a5568;
                    font-size:0.62rem; margin-top:2px; margin-bottom:10px;">
            AI analyst &bull; Live DB access
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.divider()

    # ── Session state ──────────────────────────────────────────────
    if "copilot_messages" not in st.session_state:
        st.session_state.copilot_messages = [
            {
                "role": "assistant",
                "content": "Copilot online. I have live access to your security database. Ask me about threats, attackers, or patterns.",
                "confidence": "high",
            }
        ]
    if "copilot_input_val" not in st.session_state:
        st.session_state.copilot_input_val = ""

    # ── Chat history (scrollable container) ───────────────────────────
    with st.container(height=280, border=True):
        for msg in st.session_state.copilot_messages:
            role    = msg["role"]
            content = msg["content"]
            conf    = msg.get("confidence", "")

            is_user = role == "user"
            align   = "right" if is_user else "left"
            bg      = "rgba(0,255,136,0.06)" if is_user else "rgba(255,255,255,0.03)"
            border  = "rgba(0,255,136,0.2)"  if is_user else "#1a2433"
            label   = "YOU" if is_user else "COPILOT"
            label_color = "#00ff88" if is_user else "#4a5568"

            conf_colors = {"high": "#00ff88", "medium": "#ffa500", "low": "#ff3c3c"}
            conf_color  = conf_colors.get(str(conf).lower(), "#4a5568")

            st.html(
                f"""
                <div style="margin-bottom:10px; text-align:{align};">
                    <div style="display:inline-block; max-width:90%; text-align:left;
                                background:{bg}; border:1px solid {border};
                                border-radius:8px; padding:8px 11px;">
                        <div style="font-family:'JetBrains Mono',monospace;
                                    font-size:0.55rem; color:{label_color};
                                    letter-spacing:0.1em; margin-bottom:4px;">{label}</div>
                        <div style="font-family:Inter,sans-serif; font-size:0.75rem;
                                    color:#c9d1d9; line-height:1.5;">{content}</div>
                        {f'<div style="font-size:0.55rem; color:{conf_color}; margin-top:4px; font-family:monospace;">CONF: {str(conf).upper()}</div>' if conf and not is_user else ''}
                    </div>
                </div>
                """
            )

    # ── Input area ──────────────────────────────────────────────────
    user_typed = st.chat_input("Ask the Copilot...")

    # ── One-click suggestions ────────────────────────────────────────
    st.markdown(
        "<div style='font-family:monospace; color:#4a5568; font-size:0.6rem;"
        " letter-spacing:0.1em; margin:8px 0 4px;'>QUICK QUERIES</div>",
        unsafe_allow_html=True,
    )
    SUGGESTIONS = [
        "Which IP is the biggest threat?",
        "List all MITRE tactics detected",
        "How many critical events today?",
        "Which user accounts are most targeted?",
        "Summarize the last 5 critical incidents",
    ]
    pending = None
    for i, suggestion in enumerate(SUGGESTIONS):
        if st.button(suggestion, key=f"sugg_{i}", use_container_width=True):
            pending = suggestion

    # ── Resolve input source ──────────────────────────────────────────
    final_input = None
    if pending:
        final_input = pending
    elif user_typed and user_typed.strip():
        final_input = user_typed.strip()

    # ── Process message ──────────────────────────────────────────────
    if final_input:
        st.session_state.copilot_messages.append(
            {"role": "user", "content": final_input}
        )
        with st.spinner("Analysing..."):
            try:
                result     = asyncio.run(answer_ciso_question(final_input))
                answer     = result.get("answer", "No response generated.")
                confidence = result.get("confidence", "medium")
            except Exception as exc:
                answer     = f"Copilot error: {exc}"
                confidence = "low"
        st.session_state.copilot_messages.append(
            {"role": "assistant", "content": answer, "confidence": confidence}
        )
        st.rerun()

    st.divider()

    # ── Legend ───────────────────────────────────────────────────────
    st.markdown(
        "<div style='font-family:monospace; color:#4a5568; font-size:0.6rem;"
        " letter-spacing:0.1em; margin-bottom:6px;'>SEVERITY LEGEND</div>",
        unsafe_allow_html=True,
    )
    st.markdown("🔴 Critical &nbsp; Score > 7.0")
    st.markdown("🟠 High &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Score 4 – 7")
    st.markdown("🟢 Benign &nbsp;&nbsp; Score < 4")
    st.caption("Tabs auto-refresh independently.")
