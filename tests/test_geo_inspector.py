import json
from io import BytesIO
from unittest.mock import patch

from core.formatters import INTERN_SEPARATOR_WIDTH, SEPARATOR_WIDTH, format_geolocation_block
from core.geo_inspector import inspect_geolocation


class _FakeGeoResponse:
    def __init__(self, payload: dict):
        self._buf = BytesIO(json.dumps(payload).encode("utf-8"))

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_inspect_geolocation_normalizes_fields_and_formats_output():
    sample_payload = {
        "success": True,
        "ip": "142.251.34.78",
        "country": "United States",
        "country_code": "US",
        "region": "Texas",
        "city": "Dallas",
        "latitude": 37.751,
        "longitude": -97.822,
        "timezone": {"id": "America/Chicago"},
        "connection": {
            "asn": 15169,
            "org": "Google LLC",
            "isp": "Google LLC",
        },
    }

    with patch("core.geo_inspector.urlopen", return_value=_FakeGeoResponse(sample_payload)):
        result = inspect_geolocation(ip="142.251.34.78", timeout=3.0)

    assert result["status"] == "SUCCESS"
    assert result["ip"] == "142.251.34.78"
    assert result["location"] == "Dallas, Texas, US"
    assert result["timezone"] == "America/Chicago"
    assert result["coordinates"] == "37.751, -97.822"
    assert result["asn"] == "AS15169"
    assert result["organization"] == "Google LLC"
    assert result["isp_org"] == "AS15169 Google LLC"

    compact = "\n".join(format_geolocation_block(result, full_output=False))
    assert ("-" * SEPARATOR_WIDTH) in compact
    assert "[>] Geolocation & ASN" in compact
    assert "IP Address      : 142.251.34.78" in compact
    assert "ASN             : AS15169" in compact
    assert "ISP / Org       : AS15169 Google LLC" in compact
    assert "Country         :" not in compact

    full = "\n".join(format_geolocation_block(result, full_output=True))
    assert "Country         : United States (US)" in full


def test_inspect_geolocation_skips_private_or_missing_ip():
    skipped_none = inspect_geolocation(ip=None)
    assert skipped_none["status"] == "SKIPPED"

    skipped_private = inspect_geolocation(ip="192.168.1.50")
    assert skipped_private["status"] == "SKIPPED"
    assert "192.168.1.50" in skipped_private["message"]

    rendered = "\n".join(format_geolocation_block(skipped_private, full_output=False))
    assert "[>] Geolocation & ASN" in rendered
    assert "[*]" in rendered


def test_inspect_geolocation_handles_api_error():
    with patch("core.geo_inspector.urlopen", side_effect=TimeoutError("request timed out")):
        result = inspect_geolocation(ip="142.251.34.78", timeout=1.0)

    assert result["status"] == "ERROR"
    rendered = "\n".join(format_geolocation_block(result, full_output=False))
    assert "[>] Geolocation & ASN" in rendered
    assert "[-]" in rendered
