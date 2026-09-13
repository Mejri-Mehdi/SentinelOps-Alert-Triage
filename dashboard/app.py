"""SentinelOps — Security Operations & Threat Response Console.

Interactive Streamlit dashboard visualizing real-time telemetry,
correlated incident cases, hybrid risk distribution, MITRE coverage, and SOAR actions.
"""

import sys
from pathlib import Path

# Add project root directory to sys.path so 'src' is always importable
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import json
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.config import MITRE_MAPPING
from src.correlator import AlertCorrelator
from src.ingestor import AlertIngestor
from src.models import Alert, Case, ResponseAction, get_session, init_db
from src.responder import Responder
from src.risk_engine import RiskEngine

# -----------------------------------------------------------------------------
# Streamlit Page Setup
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SentinelOps | SecOps Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #1e2530;
        border-radius: 8px;
        padding: 15px;
        border-left: 5px solid #00d2ff;
        margin-bottom: 10px;
    }
    .badge-critical { background-color: #ff4b4b; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background-color: #ff8c00; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #f0ad4e; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #5bc0de; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_data():
    """Fetch database objects into pandas DataFrames."""
    session = get_session()
    try:
        alerts = session.query(Alert).all()
        cases = session.query(Case).all()
        actions = session.query(ResponseAction).all()

        alerts_df = pd.DataFrame([
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp,
                "severity": a.severity,
                "alert_type": a.alert_type,
                "source_ip": a.source_ip,
                "user": a.user,
                "host": a.host,
                "mitre_technique": f"{a.mitre_technique_id}: {a.mitre_technique_name}" if a.mitre_technique_id else "Unmapped",
                "mitre_tactic": a.mitre_tactic or "Unknown",
                "case_id": a.case_id,
            }
            for a in alerts
        ])

        cases_df = pd.DataFrame([
            {
                "id": c.id,
                "case_id": c.case_id,
                "status": c.status,
                "priority": c.priority,
                "risk_score": c.risk_score or 0.0,
                "rule_score": c.rule_score or 0.0,
                "ml_score": c.ml_score or 0.0,
                "alert_count": c.alert_count,
                "entity_type": c.entity_type,
                "entity_value": c.entity_value,
                "created_at": c.created_at,
                "updated_at": c.updated_at,
            }
            for c in cases
        ])

        actions_df = pd.DataFrame([
            {
                "id": act.id,
                "timestamp": act.timestamp,
                "case_id": act.case_id,
                "playbook_id": act.playbook_id,
                "action_type": act.action_type,
                "target": act.target,
                "status": act.status,
                "details": act.details,
            }
            for act in actions
        ])

        return alerts_df, cases_df, actions_df
    finally:
        session.close()


# -----------------------------------------------------------------------------
# Sidebar Navigation & Filter
# -----------------------------------------------------------------------------
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("SentinelOps SOAR")
st.sidebar.caption("AI-Powered Alert Triage & Response Platform")

nav = st.sidebar.radio(
    "Navigation",
    [
        "📊 Executive Overview",
        "🚨 Live Alert Stream",
        "📁 Incident Cases",
        "🗺️ MITRE ATT&CK Matrix",
        "⚡ SOAR Actions Audit",
        "⚙️ Pipeline Control",
    ],
)

alerts_df, cases_df, actions_df = load_data()

# -----------------------------------------------------------------------------
# View 1: Executive Overview
# -----------------------------------------------------------------------------
if nav == "📊 Executive Overview":
    st.header("📊 Security Operations Overview")
    st.caption("Live aggregate threat metrics and incident telemetry posture")

    if alerts_df.empty or cases_df.empty:
        st.warning("No data found in database. Head to '⚙️ Pipeline Control' to ingest alerts.")
    else:
        # Top KPI Cards
        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        total_alerts = len(alerts_df)
        total_cases = len(cases_df)
        contained_cases = len(cases_df[cases_df["status"] == "contained"])
        crit_cases = len(cases_df[cases_df["priority"] == "critical"])

        kpi1.metric("Total Ingested Alerts", f"{total_alerts:,}")
        kpi2.metric("Correlated Incidents", f"{total_cases:,}")
        kpi3.metric("Contained Incidents (SOAR)", f"{contained_cases:,}")
        kpi4.metric("Critical Threat Incidents", f"{crit_cases:,}", delta=f"{crit_cases/max(1, total_cases)*100:.1f}% of total")

        st.divider()

        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Hybrid Risk Score Distribution")
            fig_hist = px.histogram(
                cases_df,
                x="risk_score",
                nbins=20,
                color="priority",
                color_discrete_map={
                    "critical": "#ff4b4b",
                    "high": "#ff8c00",
                    "medium": "#f0ad4e",
                    "low": "#5bc0de",
                },
                labels={"risk_score": "Composite Risk Score (0-100)"},
                title="Incident Risk Distribution (Rules + Anomaly Detection)",
            )
            fig_hist.update_layout(bargap=0.1)
            st.plotly_chart(fig_hist, use_container_width=True)

        with col_right:
            st.subheader("Alerts by Severity")
            fig_pie = px.pie(
                alerts_df,
                names="severity",
                hole=0.45,
                color="severity",
                color_discrete_map={
                    "critical": "#ff4b4b",
                    "high": "#ff8c00",
                    "medium": "#f0ad4e",
                    "low": "#5bc0de",
                },
                title="Telemetry Severity Breakdown",
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        st.subheader("Recent High-Risk Cases")
        top_cases = cases_df.sort_values(by="risk_score", ascending=False).head(5)
        st.dataframe(
            top_cases[["case_id", "priority", "risk_score", "alert_count", "entity_type", "entity_value", "status"]],
            use_container_width=True,
            hide_index=True,
        )

# -----------------------------------------------------------------------------
# View 2: Live Alert Stream
# -----------------------------------------------------------------------------
elif nav == "🚨 Live Alert Stream":
    st.header("🚨 Live Security Telemetry Feed")
    st.caption("Normalized and enriched security telemetry from endpoints, identity, and network")

    if alerts_df.empty:
        st.info("No alerts found.")
    else:
        # Filter controls
        f1, f2, f3 = st.columns(3)
        with f1:
            selected_sev = st.multiselect("Filter Severity", options=alerts_df["severity"].unique().tolist())
        with f2:
            selected_type = st.multiselect("Filter Alert Type", options=alerts_df["alert_type"].unique().tolist())
        with f3:
            search_query = st.text_input("Search (IP, User, Host, Alert ID)")

        filtered = alerts_df.copy()
        if selected_sev:
            filtered = filtered[filtered["severity"].isin(selected_sev)]
        if selected_type:
            filtered = filtered[filtered["alert_type"].isin(selected_type)]
        if search_query:
            query = search_query.lower()
            filtered = filtered[
                filtered["alert_id"].str.lower().str.contains(query)
                | filtered["source_ip"].fillna("").str.lower().str.contains(query)
                | filtered["user"].fillna("").str.lower().str.contains(query)
                | filtered["host"].fillna("").str.lower().str.contains(query)
            ]

        st.write(f"Showing **{len(filtered):,}** of **{len(alerts_df):,}** alerts")
        st.dataframe(
            filtered[["timestamp", "alert_id", "severity", "alert_type", "user", "host", "source_ip", "mitre_technique"]],
            use_container_width=True,
            hide_index=True,
        )

# -----------------------------------------------------------------------------
# View 3: Incident Cases & Drill-Down
# -----------------------------------------------------------------------------
elif nav == "📁 Incident Cases":
    st.header("📁 Correlated Security Incidents (Cases)")
    st.caption("Incidents correlated across sliding 10-minute entity windows")

    if cases_df.empty:
        st.info("No cases available. Run correlation in Pipeline Control.")
    else:
        st.dataframe(
            cases_df[["case_id", "status", "priority", "risk_score", "alert_count", "entity_type", "entity_value", "updated_at"]],
            use_container_width=True,
            hide_index=True,
        )

        st.divider()
        st.subheader("🔍 Incident Investigation & Drill-Down")
        case_options = cases_df["case_id"].tolist()
        selected_case_id = st.selectbox("Select Case to Investigate", options=case_options)

        if selected_case_id:
            correlator = AlertCorrelator()
            details = correlator.get_case_details(selected_case_id)

            if details:
                c_meta = details["case"]
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Case Priority", c_meta["priority"].upper())
                m2.metric("Risk Score", f"{c_meta['risk_score']:.1f} / 100")
                m3.metric("Associated Alerts", c_meta["alert_count"])
                m4.metric("Incident Status", c_meta["status"].upper())

                tab_alerts, tab_mitre, tab_actions = st.tabs(["Attack Timeline", "MITRE Coverage", "Containment Actions"])

                with tab_alerts:
                    st.write("Chronological sequence of alerts attached to this incident:")
                    timeline_df = pd.DataFrame(details["alerts"])
                    st.dataframe(timeline_df[["timestamp", "severity", "alert_type", "description"]], use_container_width=True, hide_index=True)

                with tab_mitre:
                    st.write("**Observed Adversary Techniques:**")
                    for tech in details["mitre_summary"]["techniques"]:
                        st.markdown(f"- `{tech}`")
                    st.write("**Observed Tactics:**")
                    for tac in details["mitre_summary"]["tactics"]:
                        st.markdown(f"- `{tac}`")

                with tab_actions:
                    session = get_session()
                    case_db = session.query(Case).filter(Case.case_id == selected_case_id).first()
                    actions_list = session.query(ResponseAction).filter(ResponseAction.case_id == case_db.id).all()
                    session.close()

                    if actions_list:
                        for act in actions_list:
                            st.success(f"⚡ **{act.action_type.upper()}** on `{act.target}` via Playbook `{act.playbook_id}` [{act.status}]")
                            st.caption(f"Audit Payload: {act.details}")
                    else:
                        st.info("No automated actions executed yet for this case.")

# -----------------------------------------------------------------------------
# View 4: MITRE ATT&CK Matrix Coverage
# -----------------------------------------------------------------------------
elif nav == "🗺️ MITRE ATT&CK Matrix":
    st.header("🗺️ MITRE ATT&CK Framework Coverage")
    st.caption("Distribution of adversary tactics and techniques observed in enterprise telemetry")

    if alerts_df.empty:
        st.info("No telemetry available.")
    else:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Tactics Observed")
            tactic_counts = alerts_df["mitre_tactic"].value_counts().reset_index()
            tactic_counts.columns = ["Tactic", "Alert Count"]
            fig_tactic = px.bar(
                tactic_counts,
                x="Alert Count",
                y="Tactic",
                orientation="h",
                color="Alert Count",
                color_continuous_scale="Blues",
                title="ATT&CK Tactics Frequency",
            )
            st.plotly_chart(fig_tactic, use_container_width=True)

        with col2:
            st.subheader("Techniques Detected")
            tech_counts = alerts_df[alerts_df["mitre_technique"] != "Unmapped"]["mitre_technique"].value_counts().reset_index()
            tech_counts.columns = ["Technique", "Alert Count"]
            fig_tech = px.bar(
                tech_counts,
                x="Alert Count",
                y="Technique",
                orientation="h",
                color="Alert Count",
                color_continuous_scale="Reds",
                title="Top Detected Threat Techniques",
            )
            st.plotly_chart(fig_tech, use_container_width=True)

# -----------------------------------------------------------------------------
# View 5: SOAR Actions Audit
# -----------------------------------------------------------------------------
elif nav == "⚡ SOAR Actions Audit":
    st.header("⚡ Automated SOAR Containment Audit")
    st.caption("Persistent audit trail of automated response actions and threat containment")

    if actions_df.empty:
        st.info("No automated actions recorded. Trigger responses in Pipeline Control.")
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Actions Executed", len(actions_df))
        unique_targets = actions_df["target"].nunique()
        c2.metric("Entities Remediated", unique_targets)
        playbooks_run = actions_df["playbook_id"].nunique()
        c3.metric("Active Playbooks Triggered", playbooks_run)

        st.subheader("Action History")
        st.dataframe(
            actions_df[["timestamp", "action_type", "target", "playbook_id", "status", "case_id"]],
            use_container_width=True,
            hide_index=True,
        )

# -----------------------------------------------------------------------------
# View 6: Pipeline Control
# -----------------------------------------------------------------------------
elif nav == "⚙️ Pipeline Control":
    st.header("⚙️ SentinelOps Pipeline Control Center")
    st.caption("Trigger individual stages of the end-to-end SecOps pipeline")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.subheader("1. Ingest Telemetry")
        st.write("Batch ingest and normalize alerts from `data/alerts.jsonl`.")
        if st.button("🚀 Ingest Alerts", use_container_width=True):
            with st.spinner("Ingesting alerts..."):
                ingestor = AlertIngestor()
                stats = ingestor.ingest_from_jsonl("data/alerts.jsonl")
                st.success(f"Ingested: {stats['ingested']} | Duplicates Dropped: {stats['duplicates']}")
                st.rerun()

    with c2:
        st.subheader("2. Correlate & Score")
        st.write("Cluster alerts into Cases and execute hybrid risk scoring.")
        if st.button("🧠 Correlate & Score", use_container_width=True):
            with st.spinner("Correlating and scoring..."):
                correlator = AlertCorrelator()
                c_stats = correlator.run_correlation()
                risk_engine = RiskEngine()
                risk_engine.train_model()
                r_stats = risk_engine.score_all_cases()
                st.success(f"New Cases: {c_stats['new_cases']} | Scored: {r_stats['total']}")
                st.rerun()

    with c3:
        st.subheader("3. Execute SOAR")
        st.write("Match incident playbooks and execute automated containment.")
        if st.button("⚡ Trigger Containment", use_container_width=True):
            with st.spinner("Executing playbooks..."):
                responder = Responder(auto_train=False)
                res_stats = responder.respond_to_all(min_risk=50.0)
                st.success(f"Contained: {res_stats['contained']} | Actions: {res_stats['actions_executed']}")
                st.rerun()