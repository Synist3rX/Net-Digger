import json
from io import BytesIO
from unittest.mock import patch

from core.blacklist_inspector import inspect_blacklist_block
from core.formatters import format_blacklist_block

SAMPLE_JSON = json.dumps(
    {
        "success": True,
        "data": {
            "query": "google.com",
            "ip": "142.251.45.14",
            "domain": "google.com",
            "results": [
                {"name": "Spamhaus ZEN", "type": "ip", "listed": False, "skipped": False},
                {"name": "Spamhaus PBL", "type": "ip", "listed": True, "skipped": False},
                {"name": "Spamhaus DBL", "type": "domain", "listed": False, "skipped": False},
                {"name": "URIBL", "type": "domain", "listed": True, "skipped": False},
            ],
            "listedCount": 2,
            "checkedCount": 4,
        },
    }
).encode("utf-8")


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._buf = BytesIO(payload)

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_inspect_blacklist_with_digdns_payload():
    with patch("core.blacklist_inspector.urlopen", return_value=_FakeResponse(SAMPLE_JSON)):
        result = inspect_blacklist_block(domain="google.com", ip="142.251.45.14")

    assert result["status"] == "SUCCESS"
    assert result["overall_status"] == "Listed"
    assert result["checked_ip"] == "142.251.45.14"
    assert result["listed_count"] == 2
    assert result["clean_count"] == 2

    rendered = "\n".join(format_blacklist_block(result, full_output=False))
    assert "Spamhaus PBL" in rendered
    assert "URIBL" in rendered
    assert "Spamhaus ZEN" not in rendered
