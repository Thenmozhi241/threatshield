"""
HTTP security header analysis service. Fetches the target over HTTPS (falls
back to HTTP) and checks for the presence of standard security headers.
"""
from __future__ import annotations

import requests

from app.utils.logger import logger

RECOMMENDED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def analyze_headers(host: str, timeout: float = 6.0) -> dict:
    """
    Return {url, status_code, headers_present, headers_missing, findings, error}.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            present = [h for h in RECOMMENDED_HEADERS if h in response.headers]
            missing = [h for h in RECOMMENDED_HEADERS if h not in response.headers]
            findings = [f"Missing recommended header: {h}" for h in missing]

            server_header = response.headers.get("Server")
            if server_header:
                findings.append(f"Server header discloses software: {server_header}")

            return {
                "url": url,
                "status_code": response.status_code,
                "headers_present": present,
                "headers_missing": missing,
                "findings": findings,
                "error": None,
            }
        except requests.RequestException as exc:
            logger.warning("Header check failed for %s: %s", url, exc)
            continue

    return {
        "url": None,
        "status_code": None,
        "headers_present": [],
        "headers_missing": RECOMMENDED_HEADERS,
        "findings": ["Host unreachable over HTTP(S)"],
        "error": "connection_failed",
    }
