"""
Basic input validation helpers used across routers/services to guard against
malformed input reaching scanning services (defense-in-depth alongside
Pydantic schema validation).
"""
import ipaddress
import re

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_valid_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    return bool(_DOMAIN_RE.match(value.strip().lower()))


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_asset_target(value: str) -> bool:
    """An asset target must be either a valid domain or a valid IP address."""
    return is_valid_domain(value) or is_valid_ip(value)


def sanitize_text(value: str, max_length: int = 500) -> str:
    """Strip control characters and trim length to reduce XSS/log-injection surface."""
    if value is None:
        return ""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)
    return cleaned[:max_length]


def is_valid_port(port: int) -> bool:
    return 1 <= port <= 65535
