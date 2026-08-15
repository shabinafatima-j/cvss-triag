
# 🛡️ CVSS-Based Vulnerability Triage Dashboard

A lightweight security tool that takes a list of CVE IDs (or a raw scan
export), pulls live CVSS data from the **free NIST NVD API**, ranks
vulnerabilities by risk tier and exploitability, and generates
plain-English remediation guidance using a **free LLM API (Groq)**.

Built to demonstrate practical, deployable AI-assisted security tooling —
no paid APIs, no infra required.

## Features

- 📥 Input via file upload, pasted CVE IDs, or bundled sample data
- 🔎 Live CVSS v3.1/v3.0/v2 lookup against the NVD
- 🚦 Automatic risk tiering (Critical / High / Medium / Low)
- ⚡ Exploitability scoring derived from the CVSS vector (attack vector,
  complexity, privileges required, user interaction)
- 🤖 AI-generated, actionable remediation recommendations (Groq free tier)
- 🧯 Fully functional **without** an LLM key — falls back to rule-based
  remediation text
- 📊 Interactive charts (severity distribution, severity vs. exploitability)
- 📤 CSV export of the full triage report

## Tech Stack

| Layer          | Choice                          |
|----------------|----------------------------------|
| UI / app       | Streamlit                        |
| Data           | Pandas                           |
| Charts         | Plotly                           |
| CVSS source    | NVD REST API v2.0 (free)         |
| LLM            | Groq API, `llama-3.1-8b-instant` (free tier) |

## Setup

```bash
git clone https://github.com/<your-username>/cvss-triage-dashboard.git
cd cvss-triage-dashboard
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

### Get a free Groq API key (optional but recommended)

1. Go to https://console.groq.com/keys
2. Sign up (no card required), create a key
3. Paste it into `.env` as `GROQ_API_KEY=...`

Without a key, the app still runs end-to-end using rule-based
remediation text instead of LLM output.

### Run

```bash
streamlit run app.py
```

Open the URL Streamlit prints (usually `http://localhost:8501`).

## Usage

1. Choose an input source in the sidebar: upload a CSV/JSON with a
   `cve_id` column, paste CVE IDs directly, or use the bundled sample set.
2. Toggle AI remediation on/off.
3. Click **Run Triage**.
4. Review the risk-tiered table and charts, then export as CSV.

## Notes on rate limits

The NVD public API allows ~5 requests/30s without a key. The app
automatically throttles requests to stay within that limit. Get a free
NVD key (link in `.env.example`) to raise this to 50 requests/30s.

## Deploying for free

The simplest option is **Streamlit Community Cloud**:

1. Push this repo to GitHub
2. Go to https://share.streamlit.io, connect the repo
3. Add `GROQ_API_KEY` (and optionally `NVD_API_KEY`) under app secrets
4. Deploy — you'll get a public URL to link on your resume/portfolio

## Project structure

```
cvss-triage-dashboard/
├── app.py                  # Streamlit UI + orchestration
├── utils/
│   ├── nvd_api.py          # NVD CVSS lookup
│   ├── scoring.py          # Risk tiering + exploitability scoring
│   └── llm.py              # Groq LLM integration + offline fallback
├── sample_data/
│   └── sample_vulns.csv    # Demo CVE list
├── requirements.txt
├── .env.example
└── README.md
```

## Possible extensions

- Support raw scanner exports (Nessus, Qualys, OpenVAS) directly
- PDF report export
- Slack/email alerting for new Critical findings
- Asset inventory matching (map CVEs to affected hosts)

## License

MIT
=======
AI-assisted CVSS vulnerability triage dashboard — pulls live CVE scores from the NVD, auto-tiers risk, and generates plain-English remediation guidance with a free LLM (Groq). Built with Streamlit + Plotly.
>>>>>>> bf641aee27e963f2781cce6ea8944203687c026e
