"""
CVSS-Based Vulnerability Triage Dashboard
Upload a list of CVE IDs (or a raw vuln scan export), auto-fetch CVSS
scores from the NVD, tier/sort by risk, and generate plain-English
remediation guidance using a free LLM API (Groq).

Run:
    streamlit run app.py
"""

import io
import time
import pandas as pd
import plotly.express as px
import streamlit as st

from utils.nvd_api import fetch_cve_batch
from utils.scoring import add_risk_columns, TIER_ORDER, TIER_COLORS
from utils.llm import summarize_remediation, llm_configured

st.set_page_config(
    page_title="CVSS Vulnerability Triage Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CVSS-Based Vulnerability Triage Dashboard")
st.caption(
    "Upload a CVE list, auto-score with NVD data, triage by risk tier, "
    "and get AI-generated remediation guidance."
)

# ---------------------------------------------------------------------------
# Sidebar — input
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("1. Input")
    input_mode = st.radio("Source", ["Upload file", "Paste CVE IDs", "Use sample data"])

    cve_ids = []
    uploaded_df = None

    if input_mode == "Upload file":
        f = st.file_uploader("CSV or JSON with a 'cve_id' column", type=["csv", "json"])
        if f is not None:
            if f.name.endswith(".csv"):
                uploaded_df = pd.read_csv(f)
            else:
                uploaded_df = pd.read_json(f)
            col = next((c for c in uploaded_df.columns if c.lower() in
                        ("cve_id", "cve", "id")), None)
            if col:
                cve_ids = uploaded_df[col].dropna().astype(str).tolist()
            else:
                st.error("No column named cve_id / cve / id found.")

    elif input_mode == "Paste CVE IDs":
        raw = st.text_area("One CVE ID per line", height=180,
                            placeholder="CVE-2024-3400\nCVE-2023-4863\nCVE-2021-44228")
        if raw.strip():
            cve_ids = [line.strip() for line in raw.splitlines() if line.strip()]

    else:
        sample_path = "sample_data/sample_vulns.csv"
        uploaded_df = pd.read_csv(sample_path)
        cve_ids = uploaded_df["cve_id"].tolist()
        st.info(f"Loaded {len(cve_ids)} sample CVEs.")

    st.header("2. Options")
    use_llm = st.checkbox(
        "Generate AI remediation summaries",
        value=True,
        help="Uses a free Groq API key (set GROQ_API_KEY). Falls back to "
             "rule-based guidance if no key is configured.",
    )
    max_items = st.slider("Max CVEs to process", 1, 100, min(30, max(len(cve_ids), 1)))

    run_btn = st.button("🚀 Run Triage", type="primary", use_container_width=True)

if not llm_configured() and use_llm:
    st.sidebar.warning(
        "No GROQ_API_KEY found — remediation text will use the built-in "
        "rule-based fallback instead of the LLM. See README for free setup."
    )

# ---------------------------------------------------------------------------
# Main — processing
# ---------------------------------------------------------------------------
if run_btn:
    if not cve_ids:
        st.error("No CVE IDs provided.")
        st.stop()

    cve_ids = cve_ids[:max_items]

    progress = st.progress(0.0, text="Fetching CVSS data from NVD…")
    records = []
    fetched = fetch_cve_batch(cve_ids, progress_cb=lambda p: progress.progress(p, text="Fetching CVSS data from NVD…"))
    progress.empty()

    df = pd.DataFrame(fetched)
    if df.empty:
        st.error("Could not retrieve data for any of the given CVE IDs.")
        st.stop()

    df = add_risk_columns(df)

    if use_llm:
        prog2 = st.progress(0.0, text="Generating remediation guidance…")
        summaries = []
        for i, row in enumerate(df.itertuples()):
            summaries.append(summarize_remediation(
                cve_id=row.cve_id,
                description=row.description,
                severity=row.risk_tier,
                vector=row.cvss_vector,
            ))
            prog2.progress((i + 1) / len(df), text="Generating remediation guidance…")
        df["remediation"] = summaries
        prog2.empty()
    else:
        df["remediation"] = "—"

    st.session_state["triage_df"] = df

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
if "triage_df" in st.session_state:
    df = st.session_state["triage_df"]

    st.subheader("Summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total CVEs", len(df))
    c2.metric("Critical", int((df.risk_tier == "Critical").sum()))
    c3.metric("High", int((df.risk_tier == "High").sum()))
    c4.metric("Avg CVSS", round(df.cvss_score.mean(), 1))

    col_a, col_b = st.columns([1, 1])
    with col_a:
        tier_counts = df.risk_tier.value_counts().reindex(TIER_ORDER).fillna(0)
        fig = px.bar(
            x=tier_counts.index, y=tier_counts.values,
            color=tier_counts.index,
            color_discrete_map=TIER_COLORS,
            labels={"x": "Risk Tier", "y": "Count"},
            title="Vulnerabilities by Risk Tier",
        )
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    with col_b:
        fig2 = px.scatter(
            df, x="cvss_score", y="exploitability_score",
            color="risk_tier", color_discrete_map=TIER_COLORS,
            hover_data=["cve_id"],
            title="Severity vs. Exploitability",
        )
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Triage Table")
    display_df = df.sort_values(
        by=["risk_tier", "cvss_score"],
        key=lambda s: s.map({t: i for i, t in enumerate(TIER_ORDER)}) if s.name == "risk_tier" else s,
        ascending=[True, False],
    )
    st.dataframe(
        display_df[["cve_id", "cvss_score", "risk_tier", "exploitability_score",
                     "cvss_vector", "description", "remediation"]],
        use_container_width=True,
        height=420,
    )

    st.subheader("Export")
    csv_buf = io.StringIO()
    display_df.to_csv(csv_buf, index=False)
    st.download_button(
        "⬇️ Download CSV report", csv_buf.getvalue(),
        file_name="cvss_triage_report.csv", mime="text/csv",
    )
else:
    st.info("Configure input in the sidebar and click **Run Triage** to begin.")
