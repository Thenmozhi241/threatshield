"""
SPF / DKIM / DMARC checking service.

All three are plain DNS TXT record lookups — no external API required:
- SPF:   a TXT record on the domain itself starting with "v=spf1"
- DMARC: a TXT record on "_dmarc.<domain>" starting with "v=DMARC1"
- DKIM:  a TXT record on "<selector>._domainkey.<domain>" — DKIM has no
         fixed location, so the caller must supply the selector (e.g. the
         value your mail provider issued, such as "google" or "selector1").
"""
from __future__ import annotations

import dns.resolver

from app.utils.logger import logger


def _lookup_txt(name: str, timeout: float = 5.0) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(name, "TXT")
        return ["".join(part.decode() if isinstance(part, bytes) else part for part in rdata.strings) for rdata in answer]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception as exc:
        logger.warning("TXT lookup failed for %s: %s", name, exc)
        return []


def check_spf(domain: str) -> dict:
    records = _lookup_txt(domain)
    spf_records = [r for r in records if r.lower().startswith("v=spf1")]
    return {
        "found": len(spf_records) > 0,
        "record": spf_records[0] if spf_records else None,
        "multiple_records_warning": len(spf_records) > 1,
    }


def check_dmarc(domain: str) -> dict:
    records = _lookup_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]
    record = dmarc_records[0] if dmarc_records else None
    policy = None
    if record:
        for part in record.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                policy = part.split("=", 1)[1]
    return {"found": record is not None, "record": record, "policy": policy}


def check_dkim(domain: str, selector: str = "default") -> dict:
    records = _lookup_txt(f"{selector}._domainkey.{domain}")
    dkim_records = [r for r in records if "v=dkim1" in r.lower() or "p=" in r.lower()]
    return {
        "found": len(dkim_records) > 0,
        "record": dkim_records[0] if dkim_records else None,
        "selector": selector,
    }


def check_email_security(domain: str, dkim_selector: str = "default") -> dict:
    return {
        "domain": domain,
        "spf": check_spf(domain),
        "dmarc": check_dmarc(domain),
        "dkim": check_dkim(domain, dkim_selector),
    }
