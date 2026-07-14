"""Unit tests for input validators (no network/DB required)."""
from app.utils.validators import is_valid_asset_target, is_valid_domain, is_valid_ip, is_valid_port, sanitize_text


def test_valid_domains():
    assert is_valid_domain("example.com")
    assert is_valid_domain("sub.example.co.uk")
    assert not is_valid_domain("not a domain")
    assert not is_valid_domain("-invalid.com")
    assert not is_valid_domain("")


def test_valid_ips():
    assert is_valid_ip("192.168.1.1")
    assert is_valid_ip("::1")
    assert not is_valid_ip("999.999.999.999")
    assert not is_valid_ip("not-an-ip")


def test_valid_asset_target():
    assert is_valid_asset_target("example.com")
    assert is_valid_asset_target("10.0.0.1")
    assert not is_valid_asset_target("<script>alert(1)</script>")


def test_valid_port():
    assert is_valid_port(80)
    assert is_valid_port(65535)
    assert not is_valid_port(0)
    assert not is_valid_port(70000)


def test_sanitize_text_strips_control_chars_and_truncates():
    dirty = "hello\x00world" + "x" * 600
    cleaned = sanitize_text(dirty, max_length=50)
    assert "\x00" not in cleaned
    assert len(cleaned) == 50
