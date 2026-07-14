"""
Reputation / blacklist checking service.

Uses public DNS-based blacklists (DNSBLs) to check whether an IP address is
listed as a known source of spam/abuse. DNSBLs are queried via simple DNS
lookups (no API key required), which is the standard mechanism most
multi-RBL checking tools use. Domains are resolved to an IP first. Lookups
run in parallel (thread pool) since each is a small, independent, I/O-bound
DNS query, so checking dozens of providers still completes in a few seconds.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import dns.resolver

from app.utils.logger import logger

# A curated list of real, established, free-to-query public DNSBLs spanning
# general spam/abuse lists, exploit/malware lists, and proxy/open-relay
# lists. This is not an exhaustive list of every DNSBL that exists, but it
# reflects the same class of providers used by well-known multi-RBL lookup
# tools.
DNSBL_PROVIDERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "aspews.ext.sorbs.net",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.dronebl.org",
    "dyna.spamrats.com",
    "noptr.spamrats.com",
    "spam.spamrats.com",
    "all.s5h.net",
    "bl.nordspam.com",
    "black.junkemailfilter.com",
    "combined.abuse.ch",
    "db.wpbl.info",
    "dnsbl.justspam.org",
    "ix.dnsbl.manitu.net",
    "korea.services.net",
    "psbl.surriel.com",
    "rbl.interserver.net",
    "relays.mail-abuse.org",
    "singular.ttk.pte.hu",
    "spamrbl.imp.ch",
    "ubl.unsubscore.com",
    "virbl.bit.nl",
    "wormrbl.imp.ch",
]

# Known real delisting pages for the more common providers, so the "Delist"
# action in the UI is genuinely useful rather than a fake button. DNSBL
# delisting is not something that can be safely automated from a third-party
# app (it requires the listed party to attest to remediation on the
# provider's own site), so this links out to the correct place instead of
# pretending to submit a delisting request on the user's behalf.
DELISTING_URLS: dict[str, str] = {
    "zen.spamhaus.org": "https://check.spamhaus.org/",
    "bl.spamcop.net": "https://www.spamcop.net/bl.shtml",
    "b.barracudacentral.org": "https://www.barracudacentral.org/rbl/removal-request",
    "dnsbl.sorbs.net": "https://www.sorbs.net/lookup.shtml",
    "aspews.ext.sorbs.net": "https://www.sorbs.net/lookup.shtml",
    "dnsbl-1.uceprotect.net": "https://www.uceprotect.net/en/rblcheck.php",
    "dnsbl-2.uceprotect.net": "https://www.uceprotect.net/en/rblcheck.php",
    "dnsbl-3.uceprotect.net": "https://www.uceprotect.net/en/rblcheck.php",
    "dnsbl.dronebl.org": "https://dronebl.org/lookup",
    "dyna.spamrats.com": "https://www.spamrats.com/removal.php",
    "noptr.spamrats.com": "https://www.spamrats.com/removal.php",
    "spam.spamrats.com": "https://www.spamrats.com/removal.php",
    "psbl.surriel.com": "https://psbl.org/remove",
    "db.wpbl.info": "https://www.wpbl.info/lookup.html",
}


def _resolve_to_ip(target: str) -> str | None:
    try:
        socket.inet_aton(target)
        return target  # already an IPv4 address
    except OSError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _query_provider(reversed_ip: str, provider: str, timeout: float) -> tuple[str, bool]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    query = f"{reversed_ip}.{provider}"
    try:
        resolver.resolve(query, "A")
        return provider, True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return provider, False
    except Exception as exc:
        logger.debug("DNSBL lookup error via %s: %s", provider, exc)
        return provider, False


def check_reputation(target: str, timeout: float = 4.0, max_workers: int = 12) -> dict:
    """
    Return {ip, listed_on: [...], is_blacklisted: bool, checked_providers: [...], error}.
    Queries all configured DNSBL providers concurrently.
    """
    ip = _resolve_to_ip(target)
    if not ip:
        return {
            "ip": None,
            "listed_on": [],
            "is_blacklisted": False,
            "checked_providers": DNSBL_PROVIDERS,
            "error": "could_not_resolve",
        }

    reversed_ip = ".".join(reversed(ip.split(".")))
    listed_on: list[str] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_query_provider, reversed_ip, provider, timeout) for provider in DNSBL_PROVIDERS
        ]
        for future in as_completed(futures):
            provider, is_listed = future.result()
            if is_listed:
                listed_on.append(provider)

    return {
        "ip": ip,
        "listed_on": listed_on,
        "is_blacklisted": len(listed_on) > 0,
        "checked_providers": DNSBL_PROVIDERS,
        "error": None,
    }


def get_delisting_url(provider: str) -> str:
    """Return a genuine delisting/lookup page for the provider, falling back
    to a search query when we don't have a specific URL on file."""
    if provider in DELISTING_URLS:
        return DELISTING_URLS[provider]
    return f"https://www.google.com/search?q={quote(provider + ' delisting removal request')}"


def get_blacklist_summary(db, asset_id: int) -> dict:
    """
    Return the most recent per-provider blacklist check results for an asset:
    {rows: [{provider, is_listed, checked_at}], listed_count, total_count, checked_at}.
    """
    from app.models.blacklist_result import BlacklistResult

    latest = (
        db.query(BlacklistResult)
        .filter(BlacklistResult.asset_id == asset_id)
        .order_by(BlacklistResult.checked_at.desc())
        .first()
    )
    if not latest:
        return {"rows": [], "listed_count": 0, "total_count": 0, "checked_at": None}

    rows = (
        db.query(BlacklistResult)
        .filter(BlacklistResult.asset_id == asset_id, BlacklistResult.checked_at == latest.checked_at)
        .order_by(BlacklistResult.provider)
        .all()
    )
    listed_count = sum(1 for r in rows if r.is_listed)
    return {
        "rows": rows,
        "listed_count": listed_count,
        "total_count": len(rows),
        "checked_at": latest.checked_at,
    }
