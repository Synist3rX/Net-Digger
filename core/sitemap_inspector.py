from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET


def _fetch_xml(url: str, timeout: float) -> tuple[bool, str, str]:
    req = Request(
        url,
        headers={
            "User-Agent": "NetDigger/1.15.0 (+https://github.com/your-username/net-digger)",
            "Accept": "application/xml, text/xml, */*",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return True, body, ""
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        return False, "", str(exc)


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1].lower() if "}" in tag else tag.lower()


def _extract_locs_from_xml(xml_text: str) -> tuple[str, list[str]]:
    """
    Returns (kind, urls) where kind is 'sitemapindex', 'urlset', or 'unknown'.
    """
    root = ET.fromstring(xml_text)
    root_name = _strip_ns(root.tag)
    locs: list[str] = []

    if root_name == "sitemapindex":
        for child in root:
            if _strip_ns(child.tag) == "sitemap":
                for sub in child:
                    if _strip_ns(sub.tag) == "loc" and sub.text and sub.text.strip():
                        locs.append(sub.text.strip())
        return "sitemapindex", locs

    if root_name == "urlset":
        for child in root:
            if _strip_ns(child.tag) == "url":
                for sub in child:
                    if _strip_ns(sub.tag) == "loc" and sub.text and sub.text.strip():
                        locs.append(sub.text.strip())
        return "urlset", locs

    for elem in root.iter():
        if _strip_ns(elem.tag) == "loc" and elem.text and elem.text.strip():
            locs.append(elem.text.strip())
    return "unknown", locs


def inspect_sitemap(
    domain: str,
    engine: Any = None,
    robots_info: dict[str, Any] | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Inspects sitemap index or URL entries using URLs from robots_info or standard sitemap paths.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain:
        return {
            "status": "ERROR",
            "domain": clean_domain,
            "message": "Invalid domain for sitemap inspection.",
        }

    effective_timeout = timeout
    if effective_timeout is None and engine is not None:
        effective_timeout = float(getattr(getattr(engine, "resolver", None), "timeout", 5.0))
    if effective_timeout is None:
        effective_timeout = 5.0

    seed_urls: list[str] = []
    if isinstance(robots_info, dict):
        for s_url in robots_info.get("sitemaps") or []:
            abs_url = urljoin(f"https://{clean_domain}/", str(s_url).strip())
            if abs_url not in seed_urls:
                seed_urls.append(abs_url)

    if not seed_urls:
        seed_urls = [
            f"https://{clean_domain}/sitemap.xml",
            f"https://{clean_domain}/sitemap_index.xml",
        ]

    errors: list[str] = []
    for candidate in seed_urls:
        ok, xml_body, err = _fetch_xml(candidate, effective_timeout)
        if not ok or not xml_body.strip():
            errors.append(f"{candidate}: {err or 'empty response'}")
            continue

        try:
            kind, urls = _extract_locs_from_xml(xml_body)
        except ET.ParseError as exc:
            errors.append(f"{candidate}: XML parse error ({exc})")
            continue

        return {
            "status": "SUCCESS",
            "domain": clean_domain,
            "sitemap_url": candidate,
            "kind": kind,
            "urls": urls,
            "url_count": len(urls),
            "badge": f"{len(urls)} sitemap URLs",
        }

    return {
        "status": "NOT_FOUND",
        "domain": clean_domain,
        "sitemap_url": seed_urls[0] if seed_urls else None,
        "kind": None,
        "urls": [],
        "url_count": 0,
        "badge": "0 sitemap URLs",
        "message": "; ".join(errors) if errors else "No sitemap found",
    }
