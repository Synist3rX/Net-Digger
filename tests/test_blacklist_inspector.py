from unittest.mock import MagicMock

from core.blacklist_inspector import build_dnsbl_query_name, inspect_blacklist_block
from core.formatters import INTERN_SEPARATOR_WIDTH, SEPARATOR_WIDTH, format_blacklist_block


def test_build_dnsbl_query_name_ip_and_domain():
    assert (
        build_dnsbl_query_name("142.251.215.238", "ip", "zen.spamhaus.org")
        == "238.215.251.142.zen.spamhaus.org"
    )
    assert build_dnsbl_query_name("Example.COM.", "domain", "dbl.spamhaus.org") == "example.com.dbl.spamhaus.org"
    # IPv6 o IP en lista de dominio debe devolver None
    assert build_dnsbl_query_name("2607:f8b0::1", "ip", "zen.spamhaus.org") is None
    assert build_dnsbl_query_name("142.251.215.238", "domain", "dbl.spamhaus.org") is None


def test_inspect_blacklist_all_clean():
    engine = MagicMock()
    engine.query_record.return_value = {"status": "NXDOMAIN", "records": []}

    providers = (
        ("Spamhaus ZEN", "ip", "zen.spamhaus.org"),
        ("Spamhaus DBL", "domain", "dbl.spamhaus.org"),
    )

    result = inspect_blacklist_block(
        domain="google.com",
        engine=engine,
        ip="142.251.215.238",
        providers=providers,
        max_workers=2,
    )

    assert result["status"] == "SUCCESS"
    assert result["overall_status"] == "Clean"
    assert result["checked_ip"] == "142.251.215.238"
    assert result["total_checked"] == 2
    assert result["clean_count"] == 2
    assert result["listed_count"] == 0
    assert result["error_count"] == 0
    assert [c["query_name"] for c in result["checks"]] == [
        "238.215.251.142.zen.spamhaus.org",
        "google.com.dbl.spamhaus.org",
    ]


def test_inspect_blacklist_detects_listed_and_errors():
    engine = MagicMock()

    def _query(qname: str, r_type: str):
        if qname == "4.3.2.1.bl.spamcop.net":
            return {"status": "SUCCESS", "records": [{"value": "127.0.0.2", "priority": None}]}
        if qname == "bad.test.dbl.spamhaus.org":
            return {"status": "TIMEOUT", "error": "DNS timeout", "records": []}
        return {"status": "NoAnswer", "records": []}

    engine.query_record.side_effect = _query

    providers = (
        ("SpamCop", "ip", "bl.spamcop.net"),
        ("Spamhaus ZEN", "ip", "zen.spamhaus.org"),
        ("Spamhaus DBL", "domain", "dbl.spamhaus.org"),
    )

    result = inspect_blacklist_block(
        domain="bad.test",
        engine=engine,
        ip="1.2.3.4",
        providers=providers,
        max_workers=2,
    )

    assert result["overall_status"] == "Listed"
    assert result["listed_count"] == 1
    assert result["clean_count"] == 1
    assert result["error_count"] == 1
    assert result["total_checked"] == 3

    by_name = {c["name"]: c for c in result["checks"]}
    assert by_name["SpamCop"]["status"] == "Listed"
    assert by_name["SpamCop"]["response"] == "127.0.0.2"
    assert by_name["Spamhaus DBL"]["status"] == "Error"
    assert by_name["Spamhaus DBL"]["message"] == "DNS timeout"


def test_inspect_blacklist_without_ip_skips_ip_lists():
    engine = MagicMock()
    engine.query_record.return_value = {"status": "NXDOMAIN", "records": []}

    providers = (
        ("Spamhaus ZEN", "ip", "zen.spamhaus.org"),
        ("URIBL", "domain", "multi.uribl.com"),
    )

    result = inspect_blacklist_block(domain="offline.test", engine=engine, ip=None, providers=providers)

    assert result["checked_ip"] == "N/A"
    assert result["total_checked"] == 1
    assert result["clean_count"] == 1
    assert result["checks"][0]["status"] == "Skipped"
    assert result["checks"][1]["status"] == "Clean"


def test_format_blacklist_block_compact_and_full():
    sample = {
        "status": "SUCCESS",
        "overall_status": "Listed",
        "checked_ip": "1.2.3.4",
        "total_checked": 2,
        "clean_count": 1,
        "listed_count": 1,
        "error_count": 0,
        "checks": [
            {"name": "Spamhaus ZEN", "scope": "ip", "status": "Clean", "response": None, "message": None},
            {"name": "SpamCop", "scope": "ip", "status": "Listed", "response": "127.0.0.2", "message": None},
        ],
    }

    compact = "\n".join(format_blacklist_block(sample, full_output=False))
    assert ("-" * SEPARATOR_WIDTH) in compact
    assert ("    " + "-" * INTERN_SEPARATOR_WIDTH) in compact
    assert "[>] Blacklist Check" in compact
    assert "Overall         : Listed" in compact
    assert "SpamCop" in compact
    assert "Spamhaus ZEN" not in compact

    full = "\n".join(format_blacklist_block(sample, full_output=True))
    assert "Spamhaus ZEN" in full
    assert "SpamCop" in full

def test_inspect_blacklist_filters_blocked_and_loopback_responses():
    engine = MagicMock()

    def _query(qname: str, r_type: str):
        if qname.endswith("zen.spamhaus.org"):
            return {"status": "SUCCESS", "records": [{"value": "127.255.255.254", "priority": None}]}
        if qname.endswith("multi.uribl.com"):
            return {"status": "SUCCESS", "records": [{"value": "127.0.0.1", "priority": None}]}
        return {"status": "NXDOMAIN", "records": []}

    engine.query_record.side_effect = _query

    providers = (
        ("Spamhaus ZEN", "ip", "zen.spamhaus.org"),
        ("URIBL", "domain", "multi.uribl.com"),
        ("SpamCop", "ip", "bl.spamcop.net"),
    )

    result = inspect_blacklist_block(
        domain="google.com",
        engine=engine,
        ip="192.178.56.174",
        providers=providers,
        max_workers=2,
    )

    assert result["listed_count"] == 0
    assert result["error_count"] == 2
    assert result["clean_count"] == 1
    assert result["overall_status"] == "Partial"
