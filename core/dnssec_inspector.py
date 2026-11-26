from typing import Any


def _has_records(query_result: dict[str, Any] | None) -> bool:
    if not isinstance(query_result, dict):
        return False
    if query_result.get("status") != "SUCCESS":
        return False
    records = query_result.get("records")
    return isinstance(records, list) and len(records) > 0


def inspect_dnssec(
    domain: str,
    engine: Any,
) -> dict[str, Any]:
    """
    Inspects DNSSEC posture for a domain using DNSKEY, DS, and Authenticated Data (AD) status.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain or engine is None:
        return {
            "status": "ERROR",
            "domain": clean_domain,
            "message": "Invalid domain or resolver engine unavailable for DNSSEC check.",
        }

    dnskey_res = engine.query_record(clean_domain, "DNSKEY")
    ds_res = engine.query_record(clean_domain, "DS")
    soa_res = engine.query_record(clean_domain, "SOA")

    dnskey_present = _has_records(dnskey_res)
    ds_present = _has_records(ds_res)

    ad_flag = False
    for res in (dnskey_res, ds_res, soa_res):
        if isinstance(res, dict) and bool(res.get("ad_flag") or res.get("authenticated_data")):
            ad_flag = True
            break

    if dnskey_present and ds_present:
        enabled = True
        status_badge = "Signed"
        config_state = "Configured"
    elif dnskey_present or ds_present:
        enabled = True
        status_badge = "Partial"
        config_state = "Partially configured"
    else:
        enabled = False
        status_badge = "Not enabled"
        config_state = "Not configured"

    return {
        "status": "SUCCESS",
        "domain": clean_domain,
        "enabled": enabled,
        "badge": status_badge,
        "config_status": config_state,
        "dnskey_record": dnskey_present,
        "ds_record": ds_present,
        "authenticated_data": ad_flag,
    }
