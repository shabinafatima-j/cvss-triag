"""
Generates plain-English remediation guidance for a vulnerability.

Primary path: Groq's free API (https://console.groq.com) — generous free
tier, no credit card required, OpenAI-compatible REST endpoint.

Fallback path: if GROQ_API_KEY is not set (or the call fails), a
rule-based template is used instead so the app is still fully usable
with zero configuration.
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")


def llm_configured() -> bool:
    return bool(os.getenv("GROQ_API_KEY"))


def _rule_based_remediation(cve_id: str, severity: str, description: str) -> str:
    urgency = {
        "Critical": "Patch immediately (within 24–48h) or isolate the affected asset.",
        "High": "Patch within your next scheduled release window (≤7 days).",
        "Medium": "Patch within the next patch cycle (≤30 days).",
        "Low": "Track and patch during routine maintenance.",
    }.get(severity, "Assess and patch based on asset criticality.")
    return (
        f"[Rule-based] {urgency} Review vendor advisory for {cve_id}, "
        f"confirm affected versions against your inventory, apply the "
        f"official patch or documented mitigation, and re-scan to verify "
        f"remediation."
    )


def summarize_remediation(cve_id: str, description: str, severity: str, vector: str) -> str:
    if not llm_configured():
        return _rule_based_remediation(cve_id, severity, description)

    prompt = (
        f"You are a security analyst. Given this vulnerability, write a "
        f"concise 2-3 sentence remediation recommendation for an engineering "
        f"team. Be specific and actionable, no fluff.\n\n"
        f"CVE: {cve_id}\n"
        f"Severity tier: {severity}\n"
        f"CVSS vector: {vector}\n"
        f"Description: {description}"
    )

    try:
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {os.getenv('GROQ_API_KEY')}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 200,
            },
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except (requests.RequestException, KeyError, IndexError):
        return _rule_based_remediation(cve_id, severity, description)
