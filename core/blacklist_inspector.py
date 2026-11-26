import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BLACKLIST_API_URL = "https://digdns.com/api/blacklist"


def fetch_blacklist_payload(query: str, timeout: float = 5.0) -> dict[str, Any]:
    """
    Queries the DigDNS blacklist API for a target domain or IP.
    """
    clean_query = query.strip()
    if not clean_query:
        return {"status": "ERROR", "message": "Empty target for blacklist check"}

    url = f"{BLACKLIST_API_URL}?{urlencode({'query': clean_query})}"
    request = Request(
        url,
        headers={
            "User-Agent": "NetDigger/1.10.0",
            "Accept": "application/json",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            raw_text = response.read().decode("utf-8", errors="replace")
            payload = json.loads(raw_text)
    except HTTPError as exc:
        return {"status": "ERROR", "message": f"Blacklist API HTTP error ({exc.code})"}
    except (URLError, TimeoutError, OSError) as exc:
        return {"status": "ERROR", "message": f"Blacklist API network error: {exc}"}
    except json.JSONDecodeError:
        return {"status": "ERROR", "message": "Invalid JSON response from blacklist API"}

    if not isinstance(payload, dict) or not payload.get("success") or not isinstance(payload.get("data"), dict):
        return {"status": "ERROR", "message": "Unexpected payload structure from blacklist API"}

    return {"status": "SUCCESS", "data": payload["data"]}


def normalize_blacklist_data(domain: str, data: dict[str, Any], fallback_ip: str | None = None) -> dict[str, Any]:
    """
    Normalizes DigDNS blacklist API 'data' into Net Digger's internal format.
    """
    raw_results = data.get("results") or []
    checks: list[dict[str, Any]] = []

    for entry in raw_results:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "Unknown"))
        scope = str(entry.get("type", "ip"))
        is_skipped = bool(entry.get("skipped", False))
        is_listed = bool(entry.get("listed", False))

        if is_skipped:
            status = "Skipped"
            response_val = None
            message = "Skipped by provider"
        elif is_listed:
            status = "Listed"
            response_val = "Listed"
            message = None
        else:
            status = "Clean"
            response_val = None
            message = None

        checks.append(
            {
                "name": name,
                "scope": scope,
                "zone": None,
                "query_name": None,
                "status": status,
                "response": response_val,
                "message": message,
            }
        )

    listed_count = int(data.get("listedCount", sum(1 for c in checks if c["status"] == "Listed")))
    skipped_count = sum(1 for c in checks if c["status"] == "Skipped")
    clean_count = sum(1 for c in checks if c["status"] == "Clean")
    total_checked = int(data.get("checkedCount", len(checks) - skipped_count))

    if listed_count > 0:
        overall_status = "Listed"
    elif skipped_count > 0 and clean_count == 0:
        overall_status = "Partial"
    else:
        overall_status = "Clean"

    checked_ip = data.get("ip") or fallback_ip or "N/A"
    checked_domain = data.get("domain") or domain.strip().lower().rstrip(".")

    return {
        "status": "SUCCESS",
        "overall_status": overall_status,
        "checked_ip": checked_ip,
        "checked_domain": checked_domain,
        "total_checked": total_checked,
        "listed_count": listed_count,
        "clean_count": clean_count,
        "error_count": 0,
        "checks": checks,
    }


def inspect_blacklist_block(
    domain: str,
    engine: Any = None,
    ip: str | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Runs blacklist inspection via DigDNS API and normalizes results for CLI/JSON output.
    """
    effective_timeout = timeout
    if effective_timeout is None and engine is not None:
        effective_timeout = float(getattr(getattr(engine, "resolver", None), "timeout", 5.0))
    if effective_timeout is None:
        effective_timeout = 5.0

    fetched = fetch_blacklist_payload(query=domain, timeout=effective_timeout)
    if fetched.get("status") != "SUCCESS":
        return {
            "status": "ERROR",
            "overall_status": "Error",
            "checked_ip": ip or "N/A",
            "checked_domain": domain.strip().lower().rstrip("."),
            "total_checked": 0,
            "listed_count": 0,
            "clean_count": 0,
            "error_count": 1,
            "message": fetched.get("message", "Blacklist check failed"),
            "checks": [],
        }

    return normalize_blacklist_data(domain=domain, data=fetched["data"], fallback_ip=ip)
