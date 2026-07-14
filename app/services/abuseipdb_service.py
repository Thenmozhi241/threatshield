"""
Optional AbuseIPDB integration.

AbuseIPDB (https://www.abuseipdb.com) is a free, public IP-reputation
database. Unlike the DNSBL checks elsewhere in this app, it requires a free
API key (see .env.example: ABUSEIPDB_API_KEY). If no key is configured, this
service reports itself as not configured rather than failing — the UI shows
setup instructions instead of an error.
"""
from __future__ import annotations

import requests

from app.config import settings
from app.utils.logger import logger

ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


def is_configured() -> bool:
    return bool(settings.abuseipdb_api_key)


def check_abuseipdb(ip: str, max_age_days: int = 90, timeout: float = 8.0) -> dict:
    if not is_configured():
        return {
            "configured": False,
            "error": "AbuseIPDB API key not configured. Add ABUSEIPDB_API_KEY to your .env file.",
        }

    try:
        response = requests.get(
            ABUSEIPDB_ENDPOINT,
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "configured": True,
            "error": None,
            "ip": data.get("ipAddress"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "is_whitelisted": data.get("isWhitelisted"),
            "last_reported_at": data.get("lastReportedAt"),
        }
    except requests.RequestException as exc:
        logger.warning("AbuseIPDB check failed for %s: %s", ip, exc)
        return {"configured": True, "error": str(exc)}
