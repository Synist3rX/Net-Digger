from unittest.mock import MagicMock

from core.dnssec_inspector import inspect_dnssec
from core.formatters import SEPARATOR_WIDTH, format_dnssec_block


def test_inspect_dnssec_signed_with_authenticated_data():
    engine = MagicMock()

    def _query(domain: str, r_type: str):
        if r_type == "DNSKEY":
            return {"status": "SUCCESS", "records": [{"value": "257 3 13 ..."}], "ad_flag": True}
        if r_type == "DS":
            return {"status": "SUCCESS", "records": [{"value": "12345 13 2 ..."}], "ad_flag": True}
        return {"status": "SUCCESS", "records": [{"value": "ns1.example.com"}], "ad_flag": True}

    engine.query_record.side_effect = _query

    result = inspect_dnssec("example.com", engine)

    assert result["status"] == "SUCCESS"
    assert result["enabled"] is True
    assert result["badge"] == "Signed"
    assert result["config_status"] == "Configured"
    assert result["dnskey_record"] is True
    assert result["ds_record"] is True
    assert result["authenticated_data"] is True

    rendered = "\n".join(format_dnssec_block(result, full_output=False))
    assert ("-" * SEPARATOR_WIDTH) in rendered
    assert "[>] DNSSEC" in rendered
    assert "Signed" in rendered
    assert "Configured" in rendered
    assert "Present" in rendered
    assert "Yes" in rendered


def test_inspect_dnssec_not_enabled():
    engine = MagicMock()
    engine.query_record.return_value = {"status": "NOERROR", "records": [], "ad_flag": False}

    result = inspect_dnssec("google.com", engine)

    assert result["status"] == "SUCCESS"
    assert result["enabled"] is False
    assert result["badge"] == "Not enabled"
    assert result["config_status"] == "Not configured"
    assert result["dnskey_record"] is False
    assert result["ds_record"] is False
    assert result["authenticated_data"] is False

    rendered = "\n".join(format_dnssec_block(result, full_output=False))
    assert "Not enabled" in rendered
    assert "Not configured" in rendered
    assert "Not found" in rendered
    assert "No" in rendered
