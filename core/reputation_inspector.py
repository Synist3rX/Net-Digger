import ipaddress
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

REPUTATION_API_URL = "https://digdns.com/api/reputation"


def _is_public_ip(ip_str: str | None) -> bool:
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_link_local
    )


def fetch_reputation_payload(query: str, timeout: float = 5.0) -> dict[str, Any]:
    """
    Fetches IP reputation data from the DigDNS reputation API.
    """
    clean_query = query.strip()
    if not clean_query:
        return {"status": "ERROR", "message": "Empty query target for reputation check"}

    url = f"{REPUTATION_API_URL}?{urlencode({'query': clean_query})}"
    request = Request(
        url,
        headers={
            "User-Agent": "NetDigger/1.14.0",
            "Accept": "application/json",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            raw_text = response.read().decode("utf-8", errors="replace")
            payload = json.loads(raw_text)
    except HTTPError as exc:
        return {"status": "ERROR", "message": f"Reputation API HTTP error ({exc.code})"}
    except (URLError, TimeoutError, OSError) as exc:
        return {"status": "ERROR", "message": f"Reputation API network error: {exc}"}
    except json.JSONDecodeError:
        return {"status": "ERROR", "message": "Invalid JSON returned by reputation API"}

    if not isinstance(payload, dict) or not payload.get("success") or not isinstance(payload.get("data"), dict):
        return {"status": "ERROR", "message": "Unexpected payload structure from reputation API"}

    return {"status": "SUCCESS", "data": payload["data"]}


def normalize_reputation_data(
    data: dict[str, Any],
    fallback_ip: str | None = None,
    geolocation_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Normalizes DigDNS reputation API 'data' into Net Digger's standard schema.
    """
    abuse = data.get("abuseipdb") if isinstance(data.get("abuseipdb"), dict) else {}
    available = bool(abuse.get("available", False))

    fallback_isp = "Unknown"
    if isinstance(geolocation_info, dict) and geolocation_info.get("status") == "SUCCESS":
        fallback_isp = str(geolocation_info.get("organization") or "Unknown")

    resolved_ip = str(abuse.get("ip") or data.get("ip") or fallback_ip or "N/A").strip()
    abuse_score = int(abuse.get("abuseScore", 0) or 0)
    total_reports = int(abuse.get("totalReports", 0) or 0)
    num_distinct_users = int(abuse.get("numDistinctUsers", 0) or 0)
    last_reported_at = str(abuse.get("lastReportedAt") or "N/A").strip()
    country_code = str(abuse.get("countryCode") or "N/A").strip()
    isp = str(abuse.get("isp") or fallback_isp or "Unknown").strip()
    usage_type = str(abuse.get("usageType") or "Unknown").strip()
    whitelisted = bool(abuse.get("isWhitelisted", False))

    return {
        "status": "SUCCESS",
        "source": "digdns_abuseipdb",
        "available": available,
        "query": str(data.get("query") or "").strip(),
        "ip": resolved_ip,
        "abuse_score": abuse_score,
        "badge": f"{abuse_score}% abuse",
        "total_reports": total_reports,
        "num_distinct_users": num_distinct_users,
        "last_reported_at": last_reported_at,
        "country_code": country_code,
        "isp": isp,
        "usage_type": usage_type,
        "whitelisted": whitelisted,
    }


def inspect_reputation(
    ip: str | None = None,
    engine: Any = None,
    geolocation_info: dict[str, Any] | None = None,
    target: str | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Inspects IP reputation via DigDNS API using the resolved IP or domain target.
    """
    query_target = (ip or target or "").strip()
    if not query_target:
        return {
            "status": "SKIPPED",
            "message": "No resolved IP or domain target available for reputation check.",
        }

    if ip and not _is_public_ip(ip) and not target:
        return {
            "status": "SKIPPED",
            "ip": ip.strip(),
            "message": f"Skipping reputation lookup for non-public IP ({ip.strip()}).",
        }

    effective_timeout = timeout
    if effective_timeout is None and engine is not None:
        effective_timeout = float(getattr(getattr(engine, "resolver", None), "timeout", 5.0))
    if effective_timeout is None:
        effective_timeout = 5.0

    fetched = fetch_reputation_payload(query=query_target, timeout=effective_timeout)
    if fetched.get("status") != "SUCCESS":
        return {
            "status": "ERROR",
            "ip": (ip or "N/A").strip(),
            "message": fetched.get("message", "Reputation lookup failed"),
        }

    return normalize_reputation_data(
        data=fetched["data"],
        fallback_ip=ip,
        geolocation_info=geolocation_info,
    )
