"""
DNS record lookup service. Queries common record types for a domain using
dnspython. IP-based assets are skipped (DNS lookups apply to domains).
"""
from __future__ import annotations

import dns.resolver

from app.utils.logger import logger

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def lookup_dns_records(domain: str, timeout: float = 5.0) -> list[dict]:
    """
    Return a list of dicts: {record_type, value, ttl} for each resolvable
    record type. Unsupported/absent record types are silently skipped.
    """
    results: list[dict] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for record_type in RECORD_TYPES:
        try:
            answer = resolver.resolve(domain, record_type)
            ttl = answer.rrset.ttl if answer.rrset else None
            for rdata in answer:
                results.append(
                    {
                        "record_type": record_type,
                        "value": rdata.to_text(),
                        "ttl": ttl,
                    }
                )
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
        except Exception as exc:  # defensive: never let a scan crash the app
            logger.warning("DNS lookup error for %s (%s): %s", domain, record_type, exc)
            continue

    return results
