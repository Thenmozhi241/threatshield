"""
Lightweight "is this server up?" checker: attempts a TCP connection (and, if
reachable, a lightweight HTTP request) to report whether a host is
responding, on which port, and how long it took.
"""
from __future__ import annotations

import socket
import time

import requests

from app.utils.logger import logger

CHECK_PORTS = [443, 80]


def check_server_status(host: str, timeout: float = 5.0) -> dict:
    """Return {is_up, responsive_port, response_time_ms, http_status, error}."""
    for port in CHECK_PORTS:
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                elapsed_ms = round((time.monotonic() - start) * 1000, 1)
                http_status = None
                scheme = "https" if port == 443 else "http"
                try:
                    response = requests.get(f"{scheme}://{host}", timeout=timeout)
                    http_status = response.status_code
                except requests.RequestException as exc:
                    logger.debug("HTTP probe failed for %s: %s", host, exc)
                return {
                    "is_up": True,
                    "responsive_port": port,
                    "response_time_ms": elapsed_ms,
                    "http_status": http_status,
                    "error": None,
                }
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.debug("TCP probe failed for %s:%s -> %s", host, port, exc)
            continue

    return {
        "is_up": False,
        "responsive_port": None,
        "response_time_ms": None,
        "http_status": None,
        "error": "Host did not respond on port 443 or 80",
    }
