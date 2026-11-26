from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError

from core.formatters import INTERN_SEPARATOR_WIDTH, SEPARATOR_WIDTH, format_sitemap_block
from core.sitemap_inspector import inspect_sitemap


class _FakeXmlResponse:
    def __init__(self, xml_body: str):
        self._buf = BytesIO(xml_body.encode("utf-8"))

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_inspect_sitemap_parses_sitemapindex_from_robots_info():
    urls_xml = "\n".join(
        [f"  <sitemap><loc>https://example.com/sitemap-{i}.xml</loc></sitemap>" for i in range(16)]
    )
    xml_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{urls_xml}\n"
        "</sitemapindex>"
    )
    robots_ctx = {"sitemaps": ["https://example.com/custom-index.xml"]}

    with patch("core.sitemap_inspector.urlopen", return_value=_FakeXmlResponse(xml_payload)) as mock_open:
        result = inspect_sitemap("example.com", robots_info=robots_ctx, timeout=3.0)

    assert mock_open.call_args[0][0].full_url == "https://example.com/custom-index.xml"
    assert result["status"] == "SUCCESS"
    assert result["kind"] == "sitemapindex"
    assert result["url_count"] == 16
    assert result["badge"] == "16 sitemap URLs"

    compact = "\n".join(format_sitemap_block(result, full_output=False))
    assert ("-" * SEPARATOR_WIDTH) in compact
    assert ("    " + "-" * INTERN_SEPARATOR_WIDTH) in compact
    assert "[>] Sitemap" in compact
    assert "more URLs; use --full for up to 50 or -o for full JSON" in compact

    full = "\n".join(format_sitemap_block(result, full_output=True))
    assert "https://example.com/sitemap-13.xml" in full
    assert "more URLs; use --full for up to 50 or -o for full JSON" not in full


def test_inspect_sitemap_parses_standard_urlset_when_no_robots_info():
    xml_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url><loc>https://example.com/</loc></url>\n"
        "  <url><loc>https://example.com/about</loc></url>\n"
        "</urlset>"
    )

    with patch("core.sitemap_inspector.urlopen", return_value=_FakeXmlResponse(xml_payload)):
        result = inspect_sitemap("example.com", robots_info=None, timeout=3.0)

    assert result["status"] == "SUCCESS"
    assert result["sitemap_url"] == "https://example.com/sitemap.xml"
    assert result["kind"] == "urlset"
    assert result["url_count"] == 2
    assert result["urls"] == ["https://example.com/", "https://example.com/about"]


def test_inspect_sitemap_returns_not_found_when_candidates_fail():
    err = HTTPError(
        url="https://example.com/sitemap.xml",
        code=404,
        msg="Not Found",
        hdrs=None,
        fp=None,
    )
    with patch("core.sitemap_inspector.urlopen", side_effect=err):
        result = inspect_sitemap("example.com", timeout=2.0)

    assert result["status"] == "NOT_FOUND"
    assert result["url_count"] == 0
    rendered = "\n".join(format_sitemap_block(result, full_output=False))
    assert "[>] Sitemap" in rendered
    assert "[*]" in rendered
