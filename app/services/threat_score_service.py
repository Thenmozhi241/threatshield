"""
Threat score calculation service.

Combines findings from SSL, WHOIS/domain-expiry, port scans, header
analysis, and reputation checks into a single 0-100 risk score using a
simple, transparent weighted-factor model (suitable for a portfolio /
final-year project; a production SOC tool would tune these weights against
real incident data).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

RISK_THRESHOLDS = [
    (80, "critical"),
    (50, "high"),
    (25, "medium"),
    (0, "low"),
]


def _risk_level_for(score: float) -> str:
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return "low"


def calculate_threat_score(
    ssl_result: dict | None = None,
    whois_result: dict | None = None,
    port_results: list[dict] | None = None,
    header_result: dict | None = None,
    reputation_result: dict | None = None,
) -> dict:
    """
    Return {score: float, risk_level: str, factors: json-str}.
    Higher score = higher risk. Score is clamped to [0, 100].
    """
    score = 0.0
    factors: dict[str, float] = {}

    # SSL factors
    if ssl_result:
        if ssl_result.get("error_message") or not ssl_result.get("is_valid"):
            score += 15
            factors["ssl_unreachable_or_invalid"] = 15
        elif ssl_result.get("is_expired"):
            score += 25
            factors["ssl_expired"] = 25
        else:
            days_remaining = ssl_result.get("days_remaining")
            if days_remaining is not None and days_remaining < 14:
                score += 15
                factors["ssl_expiring_soon"] = 15
            elif days_remaining is not None and days_remaining < 30:
                score += 8
                factors["ssl_expiring_within_30d"] = 8

    # Domain expiry factors
    if whois_result:
        expiration_date = whois_result.get("expiration_date")
        if isinstance(expiration_date, datetime):
            now = datetime.now(expiration_date.tzinfo) if expiration_date.tzinfo else datetime.now()
            days_left = (expiration_date - now).days
            if days_left < 0:
                score += 30
                factors["domain_expired"] = 30
            elif days_left < 15:
                score += 20
                factors["domain_expiring_soon"] = 20
            elif days_left < 30:
                score += 10
                factors["domain_expiring_within_30d"] = 10

    # Open-port factors (risky ports weighted higher)
    if port_results:
        risky_ports = {21, 23, 3389, 3306, 5432, 6379, 27017, 445}
        open_risky = [p for p in port_results if p.get("is_open") and p.get("port") in risky_ports]
        open_other = [p for p in port_results if p.get("is_open") and p.get("port") not in risky_ports]
        if open_risky:
            increment = min(25, len(open_risky) * 8)
            score += increment
            factors["risky_open_ports"] = increment
        if open_other:
            increment = min(10, len(open_other) * 2)
            score += increment
            factors["other_open_ports"] = increment

    # Security header factors
    if header_result:
        missing = header_result.get("headers_missing") or []
        if header_result.get("error"):
            score += 5
            factors["headers_unreachable"] = 5
        elif missing:
            increment = min(15, len(missing) * 2.5)
            score += increment
            factors["missing_security_headers"] = increment

    # Reputation/blacklist factors
    if reputation_result and reputation_result.get("is_blacklisted"):
        listed_count = len(reputation_result.get("listed_on", []))
        increment = min(30, 15 + listed_count * 5)
        score += increment
        factors["blacklisted"] = increment

    score = round(min(score, 100.0), 2)
    return {
        "score": score,
        "risk_level": _risk_level_for(score),
        "factors": json.dumps(factors),
    }
