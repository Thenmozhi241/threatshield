"""Unit tests for the threat score calculation service (pure function, no I/O)."""
from app.services.threat_score_service import calculate_threat_score


def test_no_findings_gives_low_score():
    result = calculate_threat_score()
    assert result["score"] == 0.0
    assert result["risk_level"] == "low"


def test_expired_ssl_increases_score():
    result = calculate_threat_score(ssl_result={"is_valid": True, "is_expired": True})
    assert result["score"] >= 25
    assert result["risk_level"] in ("medium", "high", "critical")


def test_blacklisted_reputation_is_high_risk_factor():
    result = calculate_threat_score(
        reputation_result={"is_blacklisted": True, "listed_on": ["zen.spamhaus.org", "bl.spamcop.net"]}
    )
    assert result["score"] > 0
    assert "blacklisted" in result["factors"]


def test_risky_open_ports_increase_score():
    port_results = [
        {"port": 3389, "is_open": True},
        {"port": 22, "is_open": False},
    ]
    result = calculate_threat_score(port_results=port_results)
    assert result["score"] > 0


def test_score_never_exceeds_100():
    result = calculate_threat_score(
        ssl_result={"is_valid": False, "error_message": "timeout"},
        reputation_result={"is_blacklisted": True, "listed_on": ["a", "b", "c", "d"]},
        port_results=[{"port": p, "is_open": True} for p in (21, 23, 3389, 3306, 5432, 6379, 27017, 445)],
        header_result={"headers_missing": ["A", "B", "C", "D", "E", "F"], "error": None},
    )
    assert result["score"] <= 100.0
    assert result["risk_level"] == "critical"
