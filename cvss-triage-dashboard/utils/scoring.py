"""
Risk tiering and exploitability heuristics on top of raw CVSS data.
"""

import pandas as pd

TIER_ORDER = ["Critical", "High", "Medium", "Low"]

TIER_COLORS = {
    "Critical": "#b91c1c",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#16a34a",
}

# CVSS v3.x vector abbreviations that raise exploitability
_EASY_ATTACK_VECTOR = {"AV:N"}   # Network
_LOW_COMPLEXITY = {"AC:L"}
_NO_PRIV_REQUIRED = {"PR:N"}
_NO_USER_INTERACTION = {"UI:N"}


def _tier_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _exploitability_from_vector(vector: str, fallback_score: float) -> float:
    """
    Rough 0-10 exploitability proxy from the CVSS vector string.
    Network + low complexity + no privileges + no user interaction
    scores highest (easiest to exploit at scale).
    """
    if not vector:
        return round(fallback_score * 0.7, 1)  # crude fallback

    parts = set(vector.split("/"))
    points = 0
    points += 3 if parts & _EASY_ATTACK_VECTOR else 0
    points += 2 if parts & _LOW_COMPLEXITY else 0
    points += 2 if parts & _NO_PRIV_REQUIRED else 0
    points += 2 if parts & _NO_USER_INTERACTION else 0
    points += 1  # base
    return round(min(points, 10), 1)


def add_risk_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["risk_tier"] = df["cvss_score"].apply(_tier_from_score)
    df["exploitability_score"] = df.apply(
        lambda r: _exploitability_from_vector(r.get("cvss_vector", ""), r["cvss_score"]),
        axis=1,
    )
    return df
