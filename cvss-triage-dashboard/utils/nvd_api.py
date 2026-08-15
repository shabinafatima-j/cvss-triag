"""
Fetches CVE / CVSS data from the free NIST NVD API (v2.0).
No API key required for light use (public rate limit: 5 req/30s).
Set NVD_API_KEY in .env to raise the limit to 50 req/30s.
"""

import os
import time
import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _headers():
    key = os.getenv("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def _extract_cvss(metrics: dict):
    """Prefer CVSS v3.1, fall back to v3.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            m = metrics[key][0]["cvssData"]
            return m["baseScore"], m["vectorString"], m.get("baseSeverity", "")
    if metrics.get("cvssMetricV2"):
        m = metrics["cvssMetricV2"][0]["cvssData"]
        return m["baseScore"], m["vectorString"], ""
    return None, None, None


def fetch_single_cve(cve_id: str) -> dict | None:
    try:
        resp = requests.get(
            NVD_BASE, params={"cveId": cve_id}, headers=_headers(), timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve = vulns[0]["cve"]
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        score, vector, severity = _extract_cvss(cve.get("metrics", {}))
        if score is None:
            return None
        return {
            "cve_id": cve_id,
            "description": desc[:400],
            "cvss_score": score,
            "cvss_vector": vector,
            "nvd_severity": severity,
            "published": cve.get("published", ""),
        }
    except (requests.RequestException, KeyError, IndexError):
        return None


def fetch_cve_batch(cve_ids: list[str], progress_cb=None) -> list[dict]:
    """
    Fetch each CVE sequentially with a small delay to respect the
    unauthenticated NVD rate limit (5 requests / 30s).
    """
    results = []
    has_key = bool(os.getenv("NVD_API_KEY"))
    delay = 0.6 if has_key else 6.5  # NVD public limit: 5 req/30s ≈ 1 req/6s

    for i, cve_id in enumerate(cve_ids):
        cve_id = cve_id.strip().upper()
        record = fetch_single_cve(cve_id)
        if record:
            results.append(record)
        if progress_cb:
            progress_cb((i + 1) / len(cve_ids))
        if i < len(cve_ids) - 1:
            time.sleep(delay)
    return results
