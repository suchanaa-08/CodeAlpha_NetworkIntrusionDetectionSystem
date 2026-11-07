
import json
import pandas as pd
import streamlit as st
import plotly.express as px
from pathlib import Path

# Project directories
BASE_DIR = Path(__file__).resolve().parents[1]

EVE_FILE = BASE_DIR / "logs" / "eve.json"
RESPONSE_FILE = BASE_DIR / "logs" / "response.jsonl"

# Page configuration
st.set_page_config(
    page_title="NIDS Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Network Intrusion Detection System")
st.caption("Real-time network security monitoring dashboard")

# Read Suricata alerts
def load_alerts():

    alerts = []

    if EVE_FILE.exists():

        with open(EVE_FILE, "r", encoding="utf-8") as file:

            for line in file:

                try:
                    event = json.loads(line)

                    if event.get("event_type") == "alert":

                        alert = event.get("alert", {})

                        alerts.append({
                            "Timestamp": event.get("timestamp"),
                            "Source IP": event.get("src_ip"),
                            "Destination IP": event.get("dest_ip"),
                            "Protocol": event.get("proto"),
                            "Signature": alert.get("signature"),
                            "Severity": alert.get("severity")
                        })

                except json.JSONDecodeError:
                    continue

    return pd.DataFrame(alerts)


# Read response records
def load_responses():

    records = []

    if RESPONSE_FILE.exists():

        with open(RESPONSE_FILE, "r", encoding="utf-8") as file:

            for line in file:

                try:
                    records.append(json.loads(line))

                except json.JSONDecodeError:
                    continue

    return pd.DataFrame(records)


# Load data
alerts_df = load_alerts()
responses_df = load_responses()

# Dashboard metrics
total_alerts = len(alerts_df)

total_sources = (
    alerts_df["Source IP"].nunique()
    if not alerts_df.empty else 0
)

total_responses = len(responses_df)

# Summary cards
col1, col2, col3 = st.columns(3)

col1.metric("Total Alerts", total_alerts)
col2.metric("Unique Source IPs", total_sources)
col3.metric("Response Records", total_responses)

st.divider()

# Alert analysis
st.subheader("📊 Alert Analysis")

if not alerts_df.empty:

    chart1, chart2 = st.columns(2)

    with chart1:

        protocol_counts = (
            alerts_df["Protocol"]
            .value_counts()
            .reset_index()
        )

        protocol_counts.columns = ["Protocol", "Count"]

        fig1 = px.pie(
            protocol_counts,
            names="Protocol",
            values="Count",
            title="Alerts by Protocol"
        )

        st.plotly_chart(fig1, use_container_width=True)

    with chart2:

        severity_counts = (
            alerts_df["Severity"]
            .value_counts()
            .reset_index()
        )

        severity_counts.columns = ["Severity", "Count"]

        fig2 = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            title="Alerts by Severity"
        )

        st.plotly_chart(fig2, use_container_width=True)

    # Recent alerts
    st.subheader("🚨 Detected Intrusion Alerts")

    st.dataframe(
        alerts_df.sort_values("Timestamp", ascending=False),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No intrusion alerts found.")

# Response history
st.subheader("🔍 Intrusion Response History")

if not responses_df.empty:

    st.dataframe(
        responses_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No response records found.")

st.caption("NIDS | Powered by Suricata and Python")
