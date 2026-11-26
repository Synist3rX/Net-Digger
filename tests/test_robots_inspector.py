from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from core.formatters import INTERN_SEPARATOR_WIDTH, SEPARATOR_WIDTH, format_robots_block
from core.robots_inspector import inspect_robots


class _FakeTextResponse:
    def __init__(self, body: str, status: int = 200):
        self._buf = BytesIO(body.encode("utf-8"))
        self.status = status

    def read(self) -> bytes:
        return self._buf.read()

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_inspect_robots_parses_directives_and_formats_compact_vs_full():
    sample_robots = "\n".join(
        [
            "User-agent: *",
            "Disallow: /search",
            "Allow: /search/about",
            "Disallow: /admin",
            "Sitemap: https://example.com/sitemap.xml",
            "Sitemap: https://example.com/sitemap-news.xml",
            *[f"Disallow: /path-{i}" for i in range(15)],
        ]
    )

    with patch("core.robots_inspector.urlopen", return_value=_FakeTextResponse(sample_robots)):
        result = inspect_robots("example.com", timeout=3.0)

    assert result["status"] == "SUCCESS"
    assert result["url"] == "https://example.com/robots.txt"
    assert result["line_count"] == 21
    assert result["user_agents"] == ["*"]
    assert result["allow_count"] == 1
    assert result["disallow_count"] == 17
    assert result["sitemaps"] == [
        "https://example.com/sitemap.xml",
        "https://example.com/sitemap-news.xml",
    ]

    compact = "\n".join(format_robots_block(result, full_output=False))
    assert ("-" * SEPARATOR_WIDTH) in compact
    assert ("    " + "-" * INTERN_SEPARATOR_WIDTH) in compact
    assert "[>] Robots" in compact
    assert "more lines; use --full for up to 50 or -o for full JSON" in compact

    full = "\n".join(format_robots_block(result, full_output=True))
    assert "Disallow: /path-14" in full
    assert "more lines; use --full for up to 50 or -o for full JSON" not in full


def test_inspect_robots_falls_back_to_http_when_https_fails():
    def _fake_urlopen(req, timeout=5.0):
        if req.full_url.startswith("https://"):
            raise URLError("SSL handshake failed")
        return _FakeTextResponse("User-agent: *\nDisallow: /private\n")

    with patch("core.robots_inspector.urlopen", side_effect=_fake_urlopen):
        result = inspect_robots("legacy.example.com", timeout=2.0)

    assert result["status"] == "SUCCESS"
    assert result["url"] == "http://legacy.example.com/robots.txt"
    assert result["disallow_count"] == 1


def test_inspect_robots_handles_404_not_found():
    err = HTTPError(
        url="https://example.com/robots.txt",
        code=404,
        msg="Not Found",
        hdrs=None,
        fp=None,
    )
    with patch("core.robots_inspector.urlopen", side_effect=err):
        result = inspect_robots("example.com", timeout=2.0)

    assert result["status"] == "NOT_FOUND"
    rendered = "\n".join(format_robots_block(result, full_output=False))
    assert "[>] Robots" in rendered
    assert "[*]" in rendered
