"""
Automated Logfile Anomaly & Threat Classifier — SOC Dashboard
================================================================
Wazuh-style SIEM dashboard combining an unsupervised Isolation Forest anomaly
detector (TF-IDF features) with Sigma-style MITRE ATT&CK detection rules.

Run:  streamlit run app.py
"""

import json
import io
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.parser import parse_log_text
from core.ml_engine import run_anomaly_detection
from core.enricher import enrich_dataframe
from core.demo_data import generate_demo_logs
from core.mitre_rules import TACTIC_ORDER

# ---------------------------------------------------------------------------
# Page config + theme
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SOC Dashboard | Logfile Anomaly & Threat Classifier",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CSS_PATH = Path(__file__).parent / "assets" / "style.css"
if CSS_PATH.exists():
    st.markdown(f"<style>{CSS_PATH.read_text()}</style>", unsafe_allow_html=True)

PLOTLY_TEMPLATE = "plotly_dark"
SEV_COLORS = {
    "critical": "#ff4d4f",
    "medium": "#ffc53d",
    "suspicious": "#ff9f45",
    "informational": "#52c41a",
}
SEV_LABELS = {
    "critical": "CRITICAL",
    "medium": "MEDIUM",
    "suspicious": "SUSPICIOUS",
    "informational": "INFO",
}

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
if "raw_df" not in st.session_state:
    st.session_state.raw_df = None
if "enriched_df" not in st.session_state:
    st.session_state.enriched_df = None
if "page_num" not in st.session_state:
    st.session_state.page_num = 0


def compute_severity(row):
    has_mitre = len(row["mitre_hits"]) > 0
    has_anomaly = bool(row["ml_anomaly"])
    if has_mitre and has_anomaly:
        return "critical"
    if has_mitre:
        return "medium"
    if has_anomaly:
        return "suspicious"
    return "informational"


def run_pipeline(raw_text, contamination, strict_sensitivity):
    records = parse_log_text(raw_text)
    if not records:
        return None
    df = pd.DataFrame(records)
    df = run_anomaly_detection(df, contamination=contamination)
    df = enrich_dataframe(df, strict_sensitivity=strict_sensitivity)
    df["severity"] = df.apply(compute_severity, axis=1)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# Header / Navbar
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="soc-navbar">
        <div>
            <div class="brand">🛡️ SOC<span>Sentinel</span> Dashboard</div>
            <div class="subtitle">Automated Logfile Anomaly &amp; Threat Classifier — Isolation Forest + MITRE ATT&amp;CK</div>
        </div>
        <div class="status-pill">● ENGINE READY</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 📥 Data Ingestion")
    uploaded_files = st.file_uploader(
        "Upload log file(s)",
        type=["log", "txt", "json"],
        accept_multiple_files=True,
        help="Supports Windows/Sysmon text export, Linux auth.log, Apache/Nginx access logs, SSH logs, or JSON lines.",
    )
    demo_clicked = st.button("⚡ Load Demo Dataset", use_container_width=True)

    st.markdown("---")
    st.markdown("### ⚙️ ML & Rule Tuning")
    contamination = st.slider(
        "Isolation Forest Contamination Rate",
        min_value=0.01, max_value=0.20, value=0.05, step=0.01,
        help="Expected proportion of anomalous events in the dataset.",
    )
    strict_sensitivity = st.toggle(
        "Strict Rule Sensitivity (case-sensitive matching)",
        value=False,
        help="OFF = broader / case-insensitive matching (more hits). ON = stricter case-sensitive matching (fewer false positives).",
    )

    st.markdown("---")
    run_clicked = st.button("▶️ Run Analysis Pipeline", type="primary", use_container_width=True)

    st.markdown("---")
    st.caption("Pipeline: Parser → TF-IDF + Isolation Forest → MITRE/IOC Enricher")

# ---------------------------------------------------------------------------
# Ingest data
# ---------------------------------------------------------------------------
if demo_clicked:
    st.session_state.raw_df = generate_demo_logs()
    st.session_state.enriched_df = None
    st.toast("Demo dataset loaded — click Run Analysis Pipeline", icon="⚡")

if uploaded_files:
    combined = []
    for f in uploaded_files:
        combined.append(f.read().decode("utf-8", errors="ignore"))
    st.session_state.raw_df = "\n".join(combined)

if run_clicked and st.session_state.raw_df:
    with st.spinner("Parsing logs, computing TF-IDF embeddings, running Isolation Forest, matching MITRE rules..."):
        st.session_state.enriched_df = run_pipeline(
            st.session_state.raw_df, contamination, strict_sensitivity
        )
        st.session_state.page_num = 0

df = st.session_state.enriched_df

# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------
if df is None:
    st.info(
        "👋 Upload a log file (.log / .txt / .json) or click **Load Demo Dataset** in the sidebar, "
        "then hit **Run Analysis Pipeline** to begin threat hunting."
    )
    st.stop()

# ---------------------------------------------------------------------------
# KPI Metric Cards
# ---------------------------------------------------------------------------
total_logs = len(df)
total_anomalies = int(df["ml_anomaly"].sum())
total_mitre_hits = int(df["mitre_hits"].apply(len).sum())
compromised_hosts = df[df["severity"].isin(["critical", "medium"])]["host"].nunique()

k1, k2, k3, k4 = st.columns(4)
kpi_defs = [
    (k1, "Total Logs Analyzed", f"{total_logs:,}", "", "info"),
    (k2, "Statistical Anomalies", f"{total_anomalies:,}", "Isolation Forest flagged", "medium"),
    (k3, "MITRE ATT&CK Hits", f"{total_mitre_hits:,}", f"{df['mitre_hits'].apply(len).gt(0).sum()} events matched", "critical"),
    (k4, "Compromised Hosts/Assets", f"{compromised_hosts:,}", "unique hosts w/ high+ severity", "critical"),
]
for col, label, value, sub, cls in kpi_defs:
    with col:
        st.markdown(
            f"""<div class="kpi-card">
                    <div class="kpi-label">{label}</div>
                    <div class="kpi-value {cls}">{value}</div>
                    <div class="kpi-sub">{sub}</div>
                </div>""",
            unsafe_allow_html=True,
        )

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Threat Analytics Section
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header">📊 Threat Analytics</div>', unsafe_allow_html=True)

col_a, col_b = st.columns([1, 1.3])

with col_a:
    st.caption("MITRE ATT&CK Tactic Distribution")
    tactic_counts = {}
    for tactics in df["tactics"]:
        for t in tactics:
            tactic_counts[t] = tactic_counts.get(t, 0) + 1
    if tactic_counts:
        tactic_df = pd.DataFrame(
            sorted(tactic_counts.items(), key=lambda x: -x[1]), columns=["Tactic", "Hits"]
        )
        fig = px.pie(
            tactic_df, names="Tactic", values="Hits", hole=0.55,
            color_discrete_sequence=px.colors.sequential.RdBu,
        )
        fig.update_layout(template=PLOTLY_TEMPLATE, height=330, margin=dict(t=10, b=10, l=10, r=10),
                           paper_bgcolor="rgba(0,0,0,0)", legend=dict(font=dict(size=10)))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No MITRE ATT&CK rule matches in this dataset.")

with col_b:
    st.caption("Top Detected Techniques Leaderboard")
    technique_counts = {}
    for hits in df["mitre_hits"]:
        for h in hits:
            key = (h["technique_id"], h["technique_name"], h["tactic"])
            technique_counts[key] = technique_counts.get(key, 0) + 1
    if technique_counts:
        tech_rows = [
            {"Technique ID": k[0], "Technique Name": k[1], "Tactic": k[2], "Hits": v}
            for k, v in sorted(technique_counts.items(), key=lambda x: -x[1])
        ][:10]
        tech_df = pd.DataFrame(tech_rows)
        st.dataframe(
            tech_df, use_container_width=True, hide_index=True, height=330,
            column_config={"Hits": st.column_config.ProgressColumn(
                "Hits", min_value=0, max_value=max(r["Hits"] for r in tech_rows), format="%d"
            )},
        )
    else:
        st.info("No techniques detected yet.")

st.caption("Anomaly Score Timeline (colored by severity)")
timeline_df = df.copy()
timeline_df["severity_label"] = timeline_df["severity"].map(SEV_LABELS)
fig_ts = px.scatter(
    timeline_df, x="timestamp", y="anomaly_score", color="severity_label",
    color_discrete_map={SEV_LABELS[k]: v for k, v in SEV_COLORS.items()},
    hover_data=["host", "process"],
)
fig_ts.add_hline(y=0, line_dash="dot", line_color="gray", opacity=0.5)
fig_ts.update_traces(marker=dict(size=7, line=dict(width=0.5, color="rgba(255,255,255,0.3)")))
fig_ts.update_layout(
    template=PLOTLY_TEMPLATE, height=300, margin=dict(t=10, b=10, l=10, r=10),
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    legend=dict(orientation="h", yanchor="bottom", y=1.02, font=dict(size=10)),
    xaxis_title=None, yaxis_title="Outlier Score (lower = more anomalous)",
)
st.plotly_chart(fig_ts, use_container_width=True)

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Wazuh-style Event Explorer
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header">🔎 Event Explorer</div>', unsafe_allow_html=True)

f1, f2, f3, f4 = st.columns([2, 1, 1, 1])
with f1:
    search_text = st.text_input("Search raw messages", placeholder="e.g. powershell, failed password, union select...")
with f2:
    all_techniques = sorted({h["technique_id"] for hits in df["mitre_hits"] for h in hits})
    technique_filter = st.selectbox("Technique ID", ["All"] + all_techniques)
with f3:
    host_filter = st.selectbox("Host", ["All"] + sorted(df["host"].unique().tolist()))
with f4:
    severity_filter = st.selectbox("Severity", ["All", "critical", "medium", "suspicious", "informational"])

filtered = df.copy()
if search_text:
    filtered = filtered[filtered["message"].str.contains(search_text, case=False, na=False) |
                         filtered["raw"].str.contains(search_text, case=False, na=False)]
if technique_filter != "All":
    filtered = filtered[filtered["technique_ids"].apply(lambda ids: technique_filter in ids)]
if host_filter != "All":
    filtered = filtered[filtered["host"] == host_filter]
if severity_filter != "All":
    filtered = filtered[filtered["severity"] == severity_filter]

st.caption(f"Showing {len(filtered):,} of {len(df):,} events")

PAGE_SIZE = 15
total_pages = max(1, (len(filtered) - 1) // PAGE_SIZE + 1)
st.session_state.page_num = min(st.session_state.page_num, total_pages - 1)

nav1, nav2, nav3 = st.columns([1, 2, 1])
with nav1:
    if st.button("◀ Prev", disabled=st.session_state.page_num <= 0):
        st.session_state.page_num -= 1
with nav3:
    if st.button("Next ▶", disabled=st.session_state.page_num >= total_pages - 1):
        st.session_state.page_num += 1
with nav2:
    st.markdown(f"<div style='text-align:center;color:#8996ab;padding-top:6px;'>Page {st.session_state.page_num+1} of {total_pages}</div>", unsafe_allow_html=True)

start = st.session_state.page_num * PAGE_SIZE
page_df = filtered.iloc[start:start + PAGE_SIZE]

# Build Wazuh-style HTML table
def badge_html(sev):
    return f'<span class="badge badge-{sev}">{SEV_LABELS[sev]}</span>'

rows_html = ""
for _, r in page_df.iterrows():
    techs = ", ".join(r["technique_ids"]) if r["technique_ids"] else "—"
    ts_str = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if pd.notnull(r["timestamp"]) else "—"
    msg = (r["message"][:90] + "…") if len(str(r["message"])) > 90 else r["message"]
    rows_html += f"""<tr>
        <td class="mono">{ts_str}</td>
        <td>{r['host']}</td>
        <td>{r['process']}</td>
        <td>{badge_html(r['severity'])}</td>
        <td class="mono">{techs}</td>
        <td class="msg-cell" title="{str(r['message']).replace('"','&quot;')}">{msg}</td>
    </tr>"""

table_html = f"""
<div class="event-table-wrap">
<table class="event-table">
    <thead><tr>
        <th>Timestamp</th><th>Host</th><th>Process</th><th>Severity</th><th>Technique(s)</th><th>Message</th>
    </tr></thead>
    <tbody>{rows_html if rows_html else '<tr><td colspan="6" style="color:#8996ab;padding:14px;">No events match the current filters.</td></tr>'}</tbody>
</table>
</div>
"""
st.markdown(table_html, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ---- Expandable row detail (JSON viewer) ----
if len(page_df) > 0:
    st.caption("🔬 Inspect Event Detail")
    event_options = {
        f"{r['event_id']} · {r['timestamp']} · {r['host']} · {SEV_LABELS[r['severity']]}": r["event_id"]
        for _, r in page_df.iterrows()
    }
    selected_label = st.selectbox("Select event to expand", list(event_options.keys()))
    selected_id = event_options[selected_label]
    selected_row = page_df[page_df["event_id"] == selected_id].iloc[0]

    with st.expander("📄 Full Event Record (parsed fields, rule metadata, IOCs, raw payload)", expanded=True):
        detail = {
            "event_id": selected_row["event_id"],
            "timestamp": str(selected_row["timestamp"]),
            "host": selected_row["host"],
            "process": selected_row["process"],
            "pid": selected_row["pid"],
            "user": selected_row["user"],
            "source_type": selected_row["source_type"],
            "severity": selected_row["severity"],
            "ml_anomaly": bool(selected_row["ml_anomaly"]),
            "anomaly_score": float(selected_row["anomaly_score"]),
            "mitre_hits": selected_row["mitre_hits"],
            "iocs": selected_row["iocs"],
            "message": selected_row["message"],
            "raw": selected_row["raw"],
        }
        st.json(detail)

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Export & Reporting
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header">📤 Export &amp; Reporting</div>', unsafe_allow_html=True)

e1, e2, e3 = st.columns(3)

export_df = df.copy()
export_df["timestamp"] = export_df["timestamp"].astype(str)
export_df["mitre_hits"] = export_df["mitre_hits"].apply(json.dumps)
export_df["iocs"] = export_df["iocs"].apply(json.dumps)
export_df["technique_ids"] = export_df["technique_ids"].apply(lambda x: ", ".join(x))
export_df["tactics"] = export_df["tactics"].apply(lambda x: ", ".join(x))

with e1:
    csv_buf = io.StringIO()
    export_df.to_csv(csv_buf, index=False)
    st.download_button(
        "⬇️ Export Enriched Report (CSV)", data=csv_buf.getvalue(),
        file_name="soc_threat_report.csv", mime="text/csv", use_container_width=True,
    )

with e2:
    json_records = json.loads(df.drop(columns=[]).to_json(orient="records", date_format="iso"))
    st.download_button(
        "⬇️ Export Enriched Report (JSON)", data=json.dumps(json_records, indent=2, default=str),
        file_name="soc_threat_report.json", mime="application/json", use_container_width=True,
    )

with e3:
    show_summary = st.button("📋 Generate MITRE Summary", use_container_width=True)

if show_summary:
    lines = ["MITRE ATT&CK INCIDENT SUMMARY", "=" * 32, f"Total events analyzed: {total_logs}",
              f"Statistical anomalies: {total_anomalies}", f"Total MITRE hits: {total_mitre_hits}",
              f"Compromised hosts: {compromised_hosts}", "", "Tactic breakdown:"]
    for tactic in TACTIC_ORDER:
        if tactic in tactic_counts:
            lines.append(f"  - {tactic}: {tactic_counts[tactic]} hits")
    lines.append("")
    lines.append("Top techniques:")
    for k, v in sorted(technique_counts.items(), key=lambda x: -x[1])[:10]:
        lines.append(f"  - {k[0]} ({k[1]}) — {v} hits [{k[2]}]")
    summary_text = "\n".join(lines)
    st.code(summary_text, language="text")
    st.caption("Use the copy icon in the top-right of the code block above to copy this summary for incident reporting.")
