from typing import Any

from core.detector import detect_dns_provider, detect_email_provider


def inspect_dns_records_data(
    domain: str,
    engine: Any,
    record_types: list[str],
) -> dict[str, Any]:
    """
    Queries the requested DNS record types for a domain and aggregates
    queries, table rows, counts, candidate IP, and detected providers.
    """
    queries: list[dict[str, Any]] = []
    table_rows: list[tuple[str, str, str, str]] = []
    ns_values: list[str] = []
    mx_values: list[str] = []
    first_a_record: str | None = None
    total_records = 0

    normalized_types = [rt.strip().upper() for rt in record_types if rt and rt.strip()]

    for r_type in normalized_types:
        result = engine.query_record(domain, r_type)
        if not isinstance(result, dict):
            result = {
                "status": "ERROR",
                "type": r_type,
                "message": "Empty response received from DNS resolver engine.",
            }

        queries.append(result)

        if result.get("status") == "SUCCESS":
            ttl_str = f"{result.get('ttl', 0)}s"
            for rec in result.get("records", []):
                total_records += 1
                val = str(rec.get("value", ""))
                prio_str = str(rec["priority"]) if rec.get("priority") is not None else ""
                table_rows.append((result["type"], val, prio_str, ttl_str))

                if result["type"] == "A" and not first_a_record and val.strip():
                    first_a_record = val.strip()
                elif result["type"] == "NS":
                    ns_values.append(val)
                elif result["type"] == "MX":
                    mx_values.append(val)

    dns_provider = detect_dns_provider(ns_values) if "NS" in normalized_types else "Unknown"
    email_provider = detect_email_provider(mx_values) if "MX" in normalized_types else "Unknown"

    return {
        "queries": queries,
        "table_rows": table_rows,
        "total_records": total_records,
        "dns_provider": dns_provider,
        "email_provider": email_provider,
        "first_a_record": first_a_record,
    }
