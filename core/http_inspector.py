from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
)


class _RecordingRedirectHandler(HTTPRedirectHandler):
    """Records every HTTP redirect hop before following the next URL."""

    def __init__(self, hops: list[dict[str, Any]]) -> None:
        super().__init__()
        self.hops = hops

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        current_url = req.full_url
        resolved_next = urljoin(current_url, newurl) if newurl else None
        self.hops.append(
            {
                "status_code": int(code),
                "url": current_url,
                "location": resolved_next,
            }
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _normalize_headers(raw_headers: Any) -> dict[str, str]:
    normalized: dict[str, str] = {}
    if not raw_headers:
        return normalized
    for key, val in raw_headers.items():
        k = str(key).strip().lower()
        v = str(val).strip()
        if k in normalized:
            normalized[k] = f"{normalized[k]}, {v}"
        else:
            normalized[k] = v
    return normalized


def _evaluate_security_headers(headers: dict[str, str]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    present_count = 0

    for header_name in SECURITY_HEADERS:
        val = headers.get(header_name)
        is_present = val is not None and val != ""
        if is_present:
            present_count += 1
        items.append(
            {
                "name": header_name,
                "present": is_present,
                "value": val if is_present else None,
            }
        )

    return {
        "present_count": present_count,
        "total_count": len(SECURITY_HEADERS),
        "items": items,
    }


def _attempt_http_request(start_url: str, timeout: float) -> dict[str, Any]:
    hops: list[dict[str, Any]] = []
    opener = build_opener(_RecordingRedirectHandler(hops))
    req = Request(
        start_url,
        headers={
            "User-Agent": "NetDigger/1.10.0",
            "Accept": "*/*",
        },
    )

    try:
        with opener.open(req, timeout=timeout) as resp:
            status_code = int(getattr(resp, "status", resp.getcode()))
            final_url = resp.geturl()
            headers = _normalize_headers(resp.headers)
            hops.append(
                {
                    "status_code": status_code,
                    "url": final_url,
                    "location": None,
                }
            )
    except HTTPError as exc:
        status_code = int(exc.code)
        final_url = exc.geturl() or start_url
        headers = _normalize_headers(exc.headers)
        hops.append(
            {
                "status_code": status_code,
                "url": final_url,
                "location": None,
            }
        )
    except (URLError, TimeoutError, OSError) as exc:
        return {
            "status": "ERROR",
            "message": f"HTTP request failed for {start_url}: {exc}",
        }

    return {
        "status": "SUCCESS",
        "final_url": final_url,
        "status_code": status_code,
        "redirect_chain": hops,
        "security_headers": _evaluate_security_headers(headers),
        "all_headers": headers,
    }


def inspect_http_headers(
    target: str,
    engine: Any = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Inspects HTTP status, redirect chain, security headers, and full response headers.
    """
    clean_target = target.strip()
    if not clean_target:
        return {
            "status": "ERROR",
            "message": "Empty target for HTTP inspection",
            "redirect_chain": [],
            "security_headers": {"present_count": 0, "total_count": len(SECURITY_HEADERS), "items": []},
            "all_headers": {},
        }

    effective_timeout = timeout
    if effective_timeout is None and engine is not None:
        effective_timeout = float(getattr(getattr(engine, "resolver", None), "timeout", 5.0))
    if effective_timeout is None:
        effective_timeout = 5.0

    if clean_target.startswith(("http://", "https://")):
        candidates = [clean_target]
    else:
        candidates = [f"http://{clean_target}", f"https://{clean_target}"]

    last_error: dict[str, Any] | None = None
    for url in candidates:
        result = _attempt_http_request(url, timeout=effective_timeout)
        if result.get("status") == "SUCCESS":
            return result
        last_error = result

    return {
        "status": "ERROR",
        "message": (last_error or {}).get("message", "HTTP inspection failed"),
        "final_url": candidates[0],
        "status_code": None,
        "redirect_chain": [],
        "security_headers": {"present_count": 0, "total_count": len(SECURITY_HEADERS), "items": []},
        "all_headers": {},
    }
