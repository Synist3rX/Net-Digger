from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
from typing import Any

from core.resolver import DNSResolverEngine

# (Nombre visible, scope: "ip" | "domain", zona DNSBL/URIBL)
BLACKLIST_PROVIDERS: tuple[tuple[str, str, str], ...] = (
    ("Spamhaus ZEN", "ip", "zen.spamhaus.org"),
    ("Spamhaus SBL", "ip", "sbl.spamhaus.org"),
    ("Spamhaus XBL", "ip", "xbl.spamhaus.org"),
    ("Spamhaus PBL", "ip", "pbl.spamhaus.org"),
    ("SpamCop", "ip", "bl.spamcop.net"),
    ("Barracuda", "ip", "b.barracudacentral.org"),
    ("SORBS", "ip", "dnsbl.sorbs.net"),
    ("UCEPROTECT L1", "ip", "dnsbl-1.uceprotect.net"),
    ("Abuse.ch CBL", "ip", "cbl.abuseat.org"),
    ("NiX Spam", "ip", "ix.dnsbl.manitu.net"),
    ("Spamhaus DBL", "domain", "dbl.spamhaus.org"),
    ("URIBL", "domain", "multi.surbl.org"),
    ("SURBL", "domain", "multi.uribl.com"),
)

# Nota: URIBL suele usar zonas *.uribl.com y SURBL *.surbl.org; se dejan configurables
# como tuplas (name, scope, zone) para poder ajustarse o mockearse fácilmente en tests.
DEFAULT_PROVIDERS: tuple[tuple[str, str, str], ...] = (
    ("Spamhaus ZEN", "ip", "zen.spamhaus.org"),
    ("Spamhaus SBL", "ip", "sbl.spamhaus.org"),
    ("Spamhaus XBL", "ip", "xbl.spamhaus.org"),
    ("Spamhaus PBL", "ip", "pbl.spamhaus.org"),
    ("SpamCop", "ip", "bl.spamcop.net"),
    ("Barracuda", "ip", "b.barracudacentral.org"),
    ("SORBS", "ip", "dnsbl.sorbs.net"),
    ("UCEPROTECT L1", "ip", "dnsbl-1.uceprotect.net"),
    ("Abuse.ch CBL", "ip", "cbl.abuseat.org"),
    ("NiX Spam", "ip", "ix.dnsbl.manitu.net"),
    ("Spamhaus DBL", "domain", "dbl.spamhaus.org"),
    ("URIBL", "domain", "multi.uribl.com"),
    ("SURBL", "domain", "multi.surbl.org"),
)


def build_dnsbl_query_name(target: str, scope: str, zone: str) -> str | None:
    """
    Builds the DNSBL/URIBL lookup name for an IPv4 address or domain.
    Returns None if the target is incompatible with the provider scope.
    """
    clean_zone = zone.strip().strip(".")
    clean_target = target.strip().lower().rstrip(".")
    if not clean_target or not clean_zone:
        return None

    if scope == "ip":
        try:
            addr = ipaddress.ip_address(clean_target)
        except ValueError:
            return None
        if addr.version != 4:
            # La mayoría de DNSBL clásicas operan sobre octetos IPv4 invertidos
            return None
        reversed_octets = ".".join(reversed(str(addr).split(".")))
        return f"{reversed_octets}.{clean_zone}"

    if scope == "domain":
        # Evita consultar literales IP en listas de dominio
        try:
            ipaddress.ip_address(clean_target)
            return None
        except ValueError:
            return f"{clean_target}.{clean_zone}"

    return None


def _evaluate_single_provider(
    name: str,
    scope: str,
    zone: str,
    target_value: str,
    engine: DNSResolverEngine,
) -> dict[str, Any]:
    qname = build_dnsbl_query_name(target_value, scope, zone)
    if not qname:
        return {
            "name": name,
            "scope": scope,
            "zone": zone,
            "query_name": None,
            "status": "Skipped",
            "response": None,
            "message": f"No {scope} target available",
        }

    try:
        result = engine.query_record(qname, "A")
    except Exception as exc:
        return {
            "name": name,
            "scope": scope,
            "zone": zone,
            "query_name": qname,
            "status": "Error",
            "response": None,
            "message": str(exc),
        }

    if not isinstance(result, dict):
        return {
            "name": name,
            "scope": scope,
            "zone": zone,
            "query_name": qname,
            "status": "Error",
            "response": None,
            "message": "Invalid resolver response",
        }

    status = result.get("status")
    records = result.get("records") or []

    if status == "SUCCESS" and records:
        first_val = str(records[0].get("value", "")).strip() or "Listed"

        if first_val.startswith("127.255.255."):
            return {
                "name": name,
                "scope": scope,
                "zone": zone,
                "query_name": qname,
                "status": "Error",
                "response": first_val,
                "message": f"Blocked/policy response ({first_val})",
            }

        if first_val == "127.0.0.1":
            return {
                "name": name,
                "scope": scope,
                "zone": zone,
                "query_name": qname,
                "status": "Error",
                "response": first_val,
                "message": "Invalid/blocked lookup response (127.0.0.1)",
            }

        return {
            "name": name,
            "scope": scope,
            "zone": zone,
            "query_name": qname,
            "status": "Listed",
            "response": first_val,
            "message": None,
        }

    if status in {"NXDOMAIN", "NoAnswer", "NODATA"} or (status == "SUCCESS" and not records):
        return {
            "name": name,
            "scope": scope,
            "zone": zone,
            "query_name": qname,
            "status": "Clean",
            "response": None,
            "message": None,
        }

    return {
        "name": name,
        "scope": scope,
        "zone": zone,
        "query_name": qname,
        "status": "Error",
        "response": None,
        "message": result.get("error") or status or "Query failed",
    }


def inspect_blacklist_block(
    domain: str,
    engine: DNSResolverEngine,
    ip: str | None = None,
    providers: tuple[tuple[str, str, str], ...] = DEFAULT_PROVIDERS,
    max_workers: int = 8,
) -> dict[str, Any]:
    """
    Checks IP-based DNSBLs and domain-based URIBL/DBL lists concurrently.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    clean_ip = ip.strip() if ip else None

    tasks: list[tuple[str, str, str, str]] = []
    for name, scope, zone in providers:
        target_val = clean_ip if scope == "ip" else clean_domain
        tasks.append((name, scope, zone, target_val or ""))

    checks: list[dict[str, Any]] = []
    workers = max(1, min(max_workers, len(tasks))) if tasks else 1

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(_evaluate_single_provider, name, scope, zone, target_val, engine): idx
            for idx, (name, scope, zone, target_val) in enumerate(tasks)
        }
        ordered_results: list[dict[str, Any] | None] = [None] * len(tasks)
        for future in as_completed(future_map):
            idx = future_map[future]
            ordered_results[idx] = future.result()

    checks = [item for item in ordered_results if item is not None]

    listed_count = sum(1 for c in checks if c["status"] == "Listed")
    clean_count = sum(1 for c in checks if c["status"] == "Clean")
    error_count = sum(1 for c in checks if c["status"] == "Error")
    evaluated_count = listed_count + clean_count + error_count

    if listed_count > 0:
        overall_status = "Listed"
    elif error_count > 0:
        overall_status = "Partial"
    else:
        overall_status = "Clean"

    return {
        "status": "SUCCESS",
        "overall_status": overall_status,
        "checked_ip": clean_ip or "N/A",
        "checked_domain": clean_domain,
        "total_checked": evaluated_count,
        "listed_count": listed_count,
        "clean_count": clean_count,
        "error_count": error_count,
        "checks": checks,
    }
