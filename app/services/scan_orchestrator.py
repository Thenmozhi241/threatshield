"""
Scan orchestration service.

Coordinates the individual scanning services (DNS, WHOIS, SSL, ports,
headers, reputation) for a given asset, persists their results, computes an
updated threat score, and raises alerts for noteworthy findings. This is the
single entry point used by both the API ("run scan now") and the background
scheduler.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.asset import Asset
from app.models.blacklist_result import BlacklistResult
from app.models.dns_record import DNSRecord
from app.models.notification import Notification
from app.models.port_scan_result import PortScanResult
from app.models.scan_result import ScanResult
from app.models.ssl_result import SSLResult
from app.models.threat_score import ThreatScore
from app.models.whois_result import WhoisResult
from app.services import (
    dns_service,
    header_service,
    notification_service,
    port_scan_service,
    reputation_service,
    ssl_service,
    threat_score_service,
    whois_service,
)
from app.utils.logger import logger
from app.utils.validators import is_valid_domain, is_valid_ip

SCAN_TYPES = ["dns", "whois", "ssl", "ports", "headers", "reputation"]


def run_full_scan(db: Session, asset: Asset) -> ScanResult:
    """Run every applicable check for an asset and return the ScanResult record."""
    scan = ScanResult(asset_id=asset.id, scan_type="full", status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    findings_count = 0
    target = asset.name
    is_domain = is_valid_domain(target)
    is_ip = is_valid_ip(target)

    ssl_data = None
    whois_data = None
    port_data = None
    header_data = None
    reputation_data = None

    try:
        # DNS + WHOIS only make sense for domain names
        if is_domain:
            dns_records = dns_service.lookup_dns_records(target)
            for record in dns_records:
                db.add(
                    DNSRecord(
                        asset_id=asset.id,
                        record_type=record["record_type"],
                        value=record["value"],
                        ttl=record.get("ttl"),
                    )
                )
            findings_count += len(dns_records)

            whois_data = whois_service.lookup_whois(target)
            db.add(
                WhoisResult(
                    asset_id=asset.id,
                    registrar=whois_data.get("registrar"),
                    registrant_org=whois_data.get("registrant_org"),
                    creation_date=whois_data.get("creation_date"),
                    expiration_date=whois_data.get("expiration_date"),
                    updated_date=whois_data.get("updated_date"),
                    name_servers=whois_data.get("name_servers"),
                    raw_data=whois_data.get("raw_data"),
                )
            )

        # SSL, headers, ports, and reputation apply to both domains and IPs
        ssl_data = ssl_service.check_ssl_certificate(target)
        db.add(
            SSLResult(
                asset_id=asset.id,
                issuer=ssl_data.get("issuer"),
                subject=ssl_data.get("subject"),
                valid_from=ssl_data.get("valid_from"),
                valid_to=ssl_data.get("valid_to"),
                days_remaining=ssl_data.get("days_remaining"),
                is_valid=ssl_data.get("is_valid", False),
                is_expired=ssl_data.get("is_expired", False),
                protocol=ssl_data.get("protocol"),
                serial_number=ssl_data.get("serial_number"),
                error_message=ssl_data.get("error_message"),
            )
        )

        header_data = header_service.analyze_headers(target)
        findings_count += len(header_data.get("findings", []))

        port_results = port_scan_service.scan_ports(target)
        port_data = port_results
        for p in port_results:
            db.add(
                PortScanResult(
                    asset_id=asset.id,
                    port=p["port"],
                    is_open=p["is_open"],
                    service_guess=p["service_guess"],
                    banner=p.get("banner"),
                )
            )
        findings_count += sum(1 for p in port_results if p["is_open"])

        reputation_data = reputation_service.check_reputation(target)
        if reputation_data.get("is_blacklisted"):
            findings_count += len(reputation_data.get("listed_on", []))

        blacklist_checked_at = datetime.now(timezone.utc)
        for provider in reputation_data.get("checked_providers", []):
            db.add(
                BlacklistResult(
                    asset_id=asset.id,
                    provider=provider,
                    is_listed=provider in reputation_data.get("listed_on", []),
                    checked_at=blacklist_checked_at,
                )
            )

        db.commit()

        # --- Threat score ---
        score_data = threat_score_service.calculate_threat_score(
            ssl_result=ssl_data,
            whois_result=whois_data,
            port_results=port_data,
            header_result=header_data,
            reputation_result=reputation_data,
        )
        db.add(
            ThreatScore(
                asset_id=asset.id,
                score=score_data["score"],
                risk_level=score_data["risk_level"],
                factors=score_data["factors"],
            )
        )

        # --- Alert generation ---
        _generate_alerts(db, asset, ssl_data, whois_data, port_data, reputation_data, score_data)

        scan.status = "completed"
        scan.findings_count = findings_count
        scan.summary = f"Risk score: {score_data['score']} ({score_data['risk_level']})"
        scan.finished_at = datetime.now(timezone.utc)

    except Exception as exc:  # ensure a scan failure never crashes the caller
        logger.exception("Scan failed for asset %s: %s", asset.name, exc)
        scan.status = "failed"
        scan.summary = f"Scan failed: {exc}"
        scan.finished_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)
    return scan


def _generate_alerts(
    db: Session,
    asset: Asset,
    ssl_data: dict | None,
    whois_data: dict | None,
    port_data: list[dict] | None,
    reputation_data: dict | None,
    score_data: dict,
) -> None:
    new_alerts: list[Alert] = []

    if ssl_data:
        if ssl_data.get("is_expired"):
            new_alerts.append(
                Alert(
                    asset_id=asset.id,
                    severity="critical",
                    category="ssl_expiry",
                    title=f"SSL certificate expired for {asset.name}",
                    message="The SSL/TLS certificate has already expired.",
                )
            )
        elif ssl_data.get("days_remaining") is not None and ssl_data["days_remaining"] < 14:
            new_alerts.append(
                Alert(
                    asset_id=asset.id,
                    severity="warning",
                    category="ssl_expiry",
                    title=f"SSL certificate expiring soon for {asset.name}",
                    message=f"Certificate expires in {ssl_data['days_remaining']} day(s).",
                )
            )

    if whois_data:
        expiration_date = whois_data.get("expiration_date")
        if isinstance(expiration_date, datetime):
            now = datetime.now(expiration_date.tzinfo) if expiration_date.tzinfo else datetime.now()
            days_left = (expiration_date - now).days
            if days_left < 30:
                new_alerts.append(
                    Alert(
                        asset_id=asset.id,
                        severity="critical" if days_left < 0 else "warning",
                        category="domain_expiry",
                        title=f"Domain expiry approaching for {asset.name}",
                        message=f"Domain expires in {days_left} day(s).",
                    )
                )

    if port_data:
        risky_ports = {21, 23, 3389, 3306, 5432, 6379, 27017, 445}
        for p in port_data:
            if p["is_open"] and p["port"] in risky_ports:
                new_alerts.append(
                    Alert(
                        asset_id=asset.id,
                        severity="warning",
                        category="port_open",
                        title=f"Sensitive port {p['port']} open on {asset.name}",
                        message=f"Port {p['port']} ({p['service_guess']}) is open and exposed.",
                    )
                )

    if reputation_data and reputation_data.get("is_blacklisted"):
        new_alerts.append(
            Alert(
                asset_id=asset.id,
                severity="critical",
                category="reputation",
                title=f"{asset.name} is blacklisted",
                message=f"Listed on: {', '.join(reputation_data.get('listed_on', []))}",
            )
        )

    if score_data["risk_level"] in ("high", "critical"):
        new_alerts.append(
            Alert(
                asset_id=asset.id,
                severity="critical" if score_data["risk_level"] == "critical" else "warning",
                category="threat_score",
                title=f"Elevated threat score for {asset.name}",
                message=f"Current risk score is {score_data['score']} ({score_data['risk_level']}).",
            )
        )

    for alert in new_alerts:
        db.add(alert)
    db.commit()

    owner_email = asset.owner.email if asset.owner else None
    for alert in new_alerts:
        db.refresh(alert)
        result = notification_service.dispatch_alert_notifications(alert.title, alert.message, owner_email)
        for channel, outcome in result.items():
            db.add(
                Notification(
                    user_id=asset.owner_id,
                    alert_id=alert.id,
                    channel=channel,
                    message=alert.message,
                    delivery_status="sent" if outcome["sent"] else "failed",
                    error_message=outcome.get("error"),
                )
            )
    db.commit()
