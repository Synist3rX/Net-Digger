import ipaddress
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

GEO_API_BASE_URL = "https://ipwho.is"


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


def fetch_geolocation_payload(ip: str, timeout: float = 5.0) -> dict[str, Any]:
    """
    Fetches geolocation and ASN metadata for a public IP address via ipwho.is.
    """
    clean_ip = ip.strip()
    url = f"{GEO_API_BASE_URL}/{quote(clean_ip, safe=':')}"
    request = Request(
        url,
        headers={
            "User-Agent": "NetDigger/1.12.0",
            "Accept": "application/json",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            raw_text = response.read().decode("utf-8", errors="replace")
            payload = json.loads(raw_text)
    except HTTPError as exc:
        return {"status": "ERROR", "message": f"Geolocation API HTTP error ({exc.code})"}
    except (URLError, TimeoutError, OSError) as exc:
        return {"status": "ERROR", "message": f"Geolocation API network error: {exc}"}
    except json.JSONDecodeError:
        return {"status": "ERROR", "message": "Invalid JSON returned by geolocation API"}

    if not isinstance(payload, dict) or not payload.get("success", False):
        api_msg = payload.get("message") if isinstance(payload, dict) else None
        return {
            "status": "ERROR",
            "message": api_msg or "Geolocation lookup unsuccessful",
        }

    return {"status": "SUCCESS", "data": payload}


def normalize_geolocation_data(ip: str, data: dict[str, Any]) -> dict[str, Any]:
    """
    Normalizes raw geolocation/ASN payload into Net Digger's standard block schema.
    """
    country = str(data.get("country") or "").strip()
    country_code = str(data.get("country_code") or "").strip().upper()
    region = str(data.get("region") or "").strip()
    city = str(data.get("city") or "").strip()

    location_parts = [part for part in (city, region, country_code or country) if part]
    location_str = ", ".join(location_parts) if location_parts else (country_code or country or "Unknown")

    tz_raw = data.get("timezone")
    if isinstance(tz_raw, dict):
        timezone_str = str(tz_raw.get("id") or "Unknown").strip()
    else:
        timezone_str = str(tz_raw or "Unknown").strip()

    lat = data.get("latitude")
    lon = data.get("longitude")
    if lat is not None and lon is not None:
        coordinates_str = f"{lat}, {lon}"
    else:
        coordinates_str = "N/A"

    conn = data.get("connection") if isinstance(data.get("connection"), dict) else {}
    raw_asn = conn.get("asn") or data.get("asn")
    asn_str = f"AS{raw_asn}" if raw_asn and not str(raw_asn).upper().startswith("AS") else str(raw_asn or "Unknown")

    org_str = str(conn.get("org") or conn.get("isp") or data.get("org") or "Unknown").strip()

    if asn_str != "Unknown" and org_str != "Unknown":
        isp_org_str = f"{asn_str} {org_str}"
    else:
        isp_org_str = org_str if org_str != "Unknown" else asn_str

    return {
        "status": "SUCCESS",
        "ip": str(data.get("ip") or ip).strip(),
        "country": country or "Unknown",
        "country_code": country_code or "N/A",
        "region": region or "Unknown",
        "city": city or "Unknown",
        "location": location_str,
        "timezone": timezone_str,
        "coordinates": coordinates_str,
        "latitude": lat,
        "longitude": lon,
        "asn": asn_str,
        "organization": org_str,
        "isp_org": isp_org_str,
    }


def inspect_geolocation(
    ip: str | None,
    engine: Any = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """
    Resolves geolocation and ASN details for the target's IP address.
    """
    if not ip:
        return {
            "status": "SKIPPED",
            "message": "No resolved IP address available for geolocation lookup.",
        }

    if not _is_public_ip(ip):
        return {
            "status": "SKIPPED",
            "ip": ip,
            "message": f"Skipping geolocation for non-public IP address ({ip}).",
        }

    effective_timeout = timeout
    if effective_timeout is None and engine is not None:
        effective_timeout = float(getattr(getattr(engine, "resolver", None), "timeout", 5.0))
    if effective_timeout is None:
        effective_timeout = 5.0

    fetched = fetch_geolocation_payload(ip=ip, timeout=effective_timeout)
    if fetched.get("status") != "SUCCESS":
        return {
            "status": "ERROR",
            "ip": ip,
            "message": fetched.get("message", "Geolocation lookup failed"),
        }

    return normalize_geolocation_data(ip=ip, data=fetched["data"])
