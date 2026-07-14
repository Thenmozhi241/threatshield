"""
SSL/TLS certificate inspection service. Connects to the target host on port
443, retrieves the certificate, and reports validity window / expiry.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from app.utils.logger import logger

CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def check_ssl_certificate(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """
    Return a dict describing the certificate found at host:port, or an
    error dict if the connection/handshake fails (e.g. no HTTPS, timeout).
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

        valid_from = _parse_cert_date(cert.get("notBefore"))
        valid_to = _parse_cert_date(cert.get("notAfter"))
        now = datetime.now(timezone.utc)
        days_remaining = (valid_to - now).days if valid_to else None

        subject = _flatten_name(cert.get("subject"))
        issuer = _flatten_name(cert.get("issuer"))

        return {
            "issuer": issuer,
            "subject": subject,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "days_remaining": days_remaining,
            "is_valid": True,
            "is_expired": bool(valid_to and valid_to < now),
            "protocol": protocol,
            "serial_number": cert.get("serialNumber"),
            "error_message": None,
        }
    except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        logger.warning("SSL check failed for %s:%s -> %s", host, port, exc)
        return {
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "is_valid": False,
            "is_expired": False,
            "protocol": None,
            "serial_number": None,
            "error_message": str(exc),
        }


def _parse_cert_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _flatten_name(name_tuple) -> str | None:
    if not name_tuple:
        return None
    parts = []
    for rdn in name_tuple:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None
