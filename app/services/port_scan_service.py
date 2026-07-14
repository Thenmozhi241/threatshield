"""
Lightweight TCP connect-scan service.

Intended for scanning assets the organization owns/manages, as a standard
external-attack-surface check (mirrors what a `nmap -sT` connect scan does,
without needing raw sockets/root privileges). Only a curated list of common
ports is scanned by default to keep scans fast and considerate; a caller may
supply a custom port list.
"""
from __future__ import annotations

import socket

from app.utils.logger import logger
from app.utils.validators import is_valid_port

COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def scan_ports(host: str, ports: list[int] | None = None, timeout: float = 1.0) -> list[dict]:
    """
    Attempt a TCP connection to each port. Returns a list of dicts:
    {port, is_open, service_guess, banner}.
    """
    target_ports = ports or list(COMMON_PORTS.keys())
    results: list[dict] = []

    for port in target_ports:
        if not is_valid_port(port):
            continue
        is_open = False
        banner = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                is_open = result == 0
                if is_open:
                    try:
                        sock.settimeout(0.5)
                        banner_bytes = sock.recv(128)
                        banner = banner_bytes.decode(errors="ignore").strip() or None
                    except (socket.timeout, OSError):
                        banner = None
        except (socket.gaierror, OSError) as exc:
            logger.debug("Port scan connection error for %s:%s -> %s", host, port, exc)

        results.append(
            {
                "port": port,
                "is_open": is_open,
                "service_guess": COMMON_PORTS.get(port, "unknown"),
                "banner": banner,
            }
        )

    return results
