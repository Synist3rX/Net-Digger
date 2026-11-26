from io import BytesIO
from unittest.mock import patch

from core.formatters import INTERN_SEPARATOR_WIDTH, SEPARATOR_WIDTH, format_http_headers_block
from core.http_inspector import inspect_http_headers


class _FakeHTTPResponse:
    def __init__(self, body: bytes, url: str, code: int, headers: dict[str, str]):
        self._buf = BytesIO(body)
        self._url = url
        self.status = code
        self.headers = headers

    def getcode(self) -> int:
        return self.status

    def geturl(self) -> str:
        return self._url

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_inspect_http_headers_evaluates_security_and_all_headers():
    fake_resp = _FakeHTTPResponse(
        body=b"<html></html>",
        url="http://www.google.com/",
        code=200,
        headers={
            "Content-Type": "text/html; charset=ISO-8859-1",
            "X-Frame-Options": "SAMEORIGIN",
            "X-XSS-Protection": "0",
            "Server": "gws",
        },
    )

    with patch("core.http_inspector.build_opener") as mock_opener_builder:
        mock_opener = mock_opener_builder.return_value
        mock_opener.open.return_value = fake_resp

        result = inspect_http_headers("google.com", timeout=3.0)

    assert result["status"] == "SUCCESS"
    assert result["status_code"] == 200
    assert result["final_url"] == "http://www.google.com/"
    assert result["security_headers"]["present_count"] == 2
    assert result["security_headers"]["total_count"] == 7
    assert result["all_headers"]["x-frame-options"] == "SAMEORIGIN"
    assert result["all_headers"]["server"] == "gws"

    compact = "\n".join(format_http_headers_block(result, full_output=False))
    assert ("-" * SEPARATOR_WIDTH) in compact
    assert ("    " + "-" * INTERN_SEPARATOR_WIDTH) in compact
    assert "[>] HTTP & Headers" in compact
    assert "Security Headers: 2/7" in compact
    assert "All Headers" not in compact

    full = "\n".join(format_http_headers_block(result, full_output=True))
    assert "All Headers" in full
    assert "server: gws" in full


def test_inspect_http_headers_handles_network_error():
    with patch("core.http_inspector.build_opener") as mock_opener_builder:
        mock_opener = mock_opener_builder.return_value
        mock_opener.open.side_effect = TimeoutError("timed out")

        result = inspect_http_headers("unreachable.example", timeout=1.0)

    assert result["status"] == "ERROR"
    rendered = "\n".join(format_http_headers_block(result, full_output=False))
    assert "[>] HTTP & Headers" in rendered
    assert "[-]" in rendered
