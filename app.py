import os, sys, json, tempfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))

import pandas as pd
import plotly.express as px
import streamlit as st

from parsers import parse_file
from features import build_features
from detectors import detect_rules, detect_iforest
from llm_analyst import analyze_alert

SAMPLE = os.path.join(ROOT, "data", "raw", "OpenSSH_2k.log")
COLS = ["alert_id", "source_ip", "window_start", "failed_logins",
        "unique_usernames", "successful_logins", "detector"]

st.set_page_config(page_title="AI Security Analyst", layout="wide")
st.title("AI Security Analyst")
st.caption("Detects suspicious SSH login activity and explains each alert in plain language.")

# ---------------- sidebar ----------------
with st.sidebar:
    st.header("1. Log file")
    up = st.file_uploader("Upload an OpenSSH auth log (optional)", type=["log", "txt"])
    st.caption("No file uploaded: the Loghub OpenSSH sample is used.")
    st.header("2. Detection")
    brute_thr = st.slider("Brute force: failed logins per 5 min", 3, 50, 10)
    enum_thr = st.slider("Enumeration: unique usernames per 5 min", 2, 20, 5)
    use_ml = st.checkbox("Also use Isolation Forest (ML)", value=False)
    contamination = st.slider("ML: share of windows flagged", 0.01, 0.30, 0.10, 0.01,
                              disabled=not use_ml)
    st.header("3. AI explanation")
    provider = st.radio("Provider", ["mock", "gemini"],
                        help="mock = offline template, gemini = real LLM")


@st.cache_data(show_spinner="Parsing log...")
def load_events(file_bytes):
    path = SAMPLE
    tmp = None
    if file_bytes is not None:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
        f.write(file_bytes)
        f.close()
        path = tmp = f.name
    try:
        return parse_file(path)
    except Exception:
        return pd.DataFrame()
    finally:
        if tmp:
            os.remove(tmp)


events = load_events(up.getvalue() if up else None)
if events.empty:
    st.error("No SSH login events found in this file. Is it an OpenSSH auth log?")
    st.stop()

# ---------------- detection ----------------
feats = build_features(events)
alerts = detect_rules(feats, brute_thr=brute_thr, enum_thr=enum_thr)
if alerts.empty:
    alerts = pd.DataFrame(columns=COLS)
if use_ml:
    ml = detect_iforest(feats, contamination=contamination)
    ml = pd.DataFrame({"source_ip": ml["source_ip"], "window_start": ml["window"].astype(str),
                       "failed_logins": ml["failed_logins"],
                       "unique_usernames": ml["unique_usernames"],
                       "successful_logins": ml["accepted"], "detector": "isolation_forest"})
    alerts = pd.concat([alerts.drop(columns="alert_id", errors="ignore"), ml], ignore_index=True)
alerts = alerts.sort_values("failed_logins", ascending=False).reset_index(drop=True)
alerts["alert_id"] = [f"A-{i + 1:03d}" for i in range(len(alerts))]
alerts = alerts[COLS]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events parsed", len(events))
c2.metric("Distinct IPs", events["source_ip"].nunique())
c3.metric("Alerts", len(alerts))
c4.metric("IPs alerted", alerts["source_ip"].nunique())

if alerts.empty:
    st.success("No alerts with the current thresholds. Try lowering them in the sidebar.")
    st.stop()

# ---------------- alert table ----------------
st.subheader("Alerts (sorted by failed logins)")
st.dataframe(alerts, hide_index=True)
st.download_button("Download alerts as CSV", alerts.to_csv(index=False), "alerts.csv", "text/csv")

# ---------------- alert detail ----------------
st.subheader("Alert detail")
labels = {r.alert_id: f"{r.alert_id} | {r.source_ip} | {r.detector} | {r.failed_logins} failed"
          for r in alerts.itertuples()}
chosen = st.selectbox("Choose an alert", list(labels), format_func=labels.get)
row = alerts[alerts["alert_id"] == chosen].iloc[0]
alert = json.loads(row.to_json())

left, right = st.columns([1, 1])
with left:
    st.markdown("**Evidence sent to the AI**")
    st.json(alert)
    ev = events[events["source_ip"] == row["source_ip"]].copy()
    ev["minute"] = ev["timestamp"].dt.floor("min")
    counts = ev.groupby(["minute", "event_type"]).size().reset_index(name="count")
    fig = px.bar(counts, x="minute", y="count", color="event_type",
                 title=f"Activity from {row['source_ip']} (events per minute)")
    st.plotly_chart(fig)

with right:
    st.markdown("**AI analysis**")
    key = f"{provider}|{row['source_ip']}|{row['window_start']}|{row['detector']}"
    cache = st.session_state.setdefault("analyses", {})
    if st.button("Explain with AI", type="primary"):
        with st.spinner("Analysing..."):
            try:
                cache[key] = analyze_alert(alert, provider=provider)
            except Exception as e:
                cache[key] = {"error": f"AI call failed: {e}"}
    res = cache.get(key)
    if res is None:
        st.info("Click 'Explain with AI' to analyse this alert.")
    elif "error" in res:
        st.error(res["error"])
        if "raw" in res:
            st.code(res["raw"])
    else:
        sev = str(res.get("severity", "medium")).lower()
        badge = {"critical": st.error, "high": st.error, "medium": st.warning}.get(sev, st.info)
        badge(f"Severity: {sev.upper()}   |   Confidence: {res.get('confidence', '?')}")
        st.write(res.get("summary", ""))
        st.markdown(f"**Likely attack:** {res.get('likely_attack', '?')}  \n"
                    f"**MITRE technique:** {res.get('mitre_technique', '?')}")
        st.markdown("**Recommended actions**")
        for a in res.get("recommended_actions", []):
            st.markdown(f"- {a}")
        st.markdown("**Evidence that would confirm this**")
        for a in res.get("additional_evidence_needed", []):
            st.markdown(f"- {a}")