import json
from io import BytesIO
from unittest.mock import patch

from core.formatters import SEPARATOR_WIDTH, format_reputation_block
from core.reputation_inspector import inspect_reputation


class _FakeReputationResponse:
    def __init__(self, payload: dict):
        self._buf = BytesIO(json.dumps(payload).encode("utf-8"))

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_inspect_reputation_parses_digdns_payload_and_formats():
    sample_payload = {
        "success": True,
        "data": {
            "query": "google.com",
            "ip": "142.251.34.78",
            "abuseipdb": {
                "available": True,
                "ip": "142.251.34.78",
                "abuseScore": 0,
                "totalReports": 44,
                "numDistinctUsers": 3,
                "lastReportedAt": "2026-11-25T01:17:20+00:00",
                "countryCode": "US",
                "isp": "Google LLC",
                "usageType": "Content Delivery Network",
                "isWhitelisted": True,
            },
        },
    }

    with patch("core.reputation_inspector.urlopen", return_value=_FakeReputationResponse(sample_payload)):
        result = inspect_reputation(ip="142.251.34.78", target="google.com", timeout=3.0)

    assert result["status"] == "SUCCESS"
    assert result["ip"] == "142.251.34.78"
    assert result["abuse_score"] == 0
    assert result["total_reports"] == 44
    assert result["num_distinct_users"] == 3
    assert result["isp"] == "Google LLC"
    assert result["usage_type"] == "Content Delivery Network"
    assert result["last_reported_at"] == "2026-11-25T01:17:20+00:00"
    assert result["whitelisted"] is True

    rendered = "\n".join(format_reputation_block(result, full_output=False))
    assert ("-" * SEPARATOR_WIDTH) in rendered
    assert "[>] Reputation" in rendered
    assert "0% (44 reports from 3 users)" in rendered
    assert "Google LLC" in rendered
    assert "Content Delivery Network" in rendered
    assert "Yes" in rendered


def test_inspect_reputation_skips_private_ip_without_target():
    result = inspect_reputation(ip="10.0.0.5")
    assert result["status"] == "SKIPPED"

    rendered = "\n".join(format_reputation_block(result, full_output=False))
    assert "[>] Reputation" in rendered
    assert "[*]" in rendered


def test_inspect_reputation_handles_network_error():
    with patch("core.reputation_inspector.urlopen", side_effect=TimeoutError("timeout")):
        result = inspect_reputation(ip="142.251.34.78", target="google.com", timeout=1.0)

    assert result["status"] == "ERROR"
    rendered = "\n".join(format_reputation_block(result, full_output=False))
    assert "[>] Reputation" in rendered
    assert "[-]" in rendered
