import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SITEMAP_DIRECTIVE_RE = re.compile(r"^\s*sitemap\s*:\s*(\S+)\s*$", re.IGNORECASE)


def _fetch_text(url: str, timeout: float) -> tuple[bool, int | None, str, str]:
    req = Request(
        url,
        headers={
            "User-Agent": "NetDigger/1.15.0 (+https://github.com/your-username/net-digger)",
            "Accept": "text/plain, */*",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            status_code = getattr(resp, "status", None) or resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            return True, status_code, body, ""
    except HTTPError as exc:
        return False, exc.code, "", f"HTTP {exc.code}"
    except (URLError, TimeoutError, OSError) as exc:
        return False, None, "", str(exc)


def inspect_robots(
    domain: str,
    engine: Any = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Fetches and parses /robots.txt for the target domain.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain:
        return {
            "status": "ERROR",
            "domain": clean_domain,
            "message": "Invalid domain for robots.txt inspection.",
        }

    effective_timeout = timeout
    if effective_timeout is None and engine is not None:
        effective_timeout = float(getattr(getattr(engine, "resolver", None), "timeout", 5.0))
    if effective_timeout is None:
        effective_timeout = 5.0

    https_url = f"https://{clean_domain}/robots.txt"
    ok, status_code, content, err = _fetch_text(https_url, effective_timeout)
    used_url = https_url

    if not ok and status_code is None:
        http_url = f"http://{clean_domain}/robots.txt"
        ok_http, status_http, body_http, err_http = _fetch_text(http_url, effective_timeout)
        if ok_http:
            ok, status_code, content, used_url = True, status_http, body_http, http_url
        else:
            err = f"{err} | fallback HTTP: {err_http}"

    if not ok or status_code in (404, 410) or not content.strip():
        return {
            "status": "NOT_FOUND" if status_code in (404, 410) else "ERROR",
            "domain": clean_domain,
            "url": used_url,
            "http_status": status_code,
            "message": err or "robots.txt not found or empty",
            "lines": [],
            "line_count": 0,
            "sitemaps": [],
            "user_agents": [],
            "disallow_count": 0,
            "allow_count": 0,
        }

    raw_lines = content.splitlines()
    sitemaps: list[str] = []
    user_agents: list[str] = []
    disallow_count = 0
    allow_count = 0

    for line in raw_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = SITEMAP_DIRECTIVE_RE.match(line)
        if match:
            sitemap_url = match.group(1).strip()
            if sitemap_url not in sitemaps:
                sitemaps.append(sitemap_url)
            continue

        lower = stripped.lower()
        if lower.startswith("user-agent:"):
            ua = stripped.split(":", 1)[1].strip()
            if ua and ua not in user_agents:
                user_agents.append(ua)
        elif lower.startswith("disallow:"):
            disallow_count += 1
        elif lower.startswith("allow:"):
            allow_count += 1

    return {
        "status": "SUCCESS",
        "domain": clean_domain,
        "url": used_url,
        "http_status": status_code,
        "lines": raw_lines,
        "line_count": len(raw_lines),
        "sitemaps": sitemaps,
        "user_agents": user_agents,
        "disallow_count": disallow_count,
        "allow_count": allow_count,
    }
