"""
WHOIS lookup service. Retrieves registrar, registration/expiry dates, and
name servers for a domain using python-whois.
"""
from __future__ import annotations

from datetime import datetime

import whois

from app.utils.logger import logger


def _first(value):
    """WHOIS libraries sometimes return a list for fields that are usually singular."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def lookup_whois(domain: str) -> dict:
    """
    Return a normalized dict with registrar/org/dates/name_servers/raw_data.
    On failure, returns a dict with an "error" key rather than raising, so
    scans can continue for other checks.
    """
    try:
        data = whois.whois(domain)
        return {
            "registrar": _first(data.get("registrar")),
            "registrant_org": _first(data.get("org")) or _first(data.get("registrant_organization")),
            "creation_date": _coerce_date(_first(data.get("creation_date"))),
            "expiration_date": _coerce_date(_first(data.get("expiration_date"))),
            "updated_date": _coerce_date(_first(data.get("updated_date"))),
            "name_servers": ",".join(data.get("name_servers") or []) if data.get("name_servers") else None,
            "raw_data": str(data.text) if hasattr(data, "text") else str(data),
            "error": None,
        }
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {
            "registrar": None,
            "registrant_org": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": None,
            "raw_data": None,
            "error": str(exc),
        }


def _coerce_date(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    return None


def days_until_expiry(expiration_date: datetime | None) -> int | None:
    if not expiration_date:
        return None
    delta = expiration_date - datetime.now(expiration_date.tzinfo) if expiration_date.tzinfo else expiration_date - datetime.now()
    return delta.days
