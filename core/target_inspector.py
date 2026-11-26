import socket
import urllib.error
import urllib.request
from core.resolver import DNSResolverEngine


def _resolve_ptr_with_engine(domain_or_ip: str, engine: DNSResolverEngine | None = None) -> str | None:
    """
    Resolves PTR record for an IPv4/IPv6 address using DNSResolverEngine when available,
    avoiding global socket timeout mutations across threads.
    """
    ip = domain_or_ip.strip()
    if not ip:
        return None

    # Si el motor DNS soporta consulta reversa o PTR directa, intentamos primero por ahí
    if engine is not None:
        try:
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                arpa_name = ".".join(reversed(parts)) + ".in-addr.arpa"
                res = engine.query_record(arpa_name, "PTR")
                if isinstance(res, dict) and res.get("status") == "SUCCESS":
                    for rec in res.get("records", []):
                        val = str(rec.get("value", "")).strip().rstrip(".")
                        if val:
                            return val
        except Exception:
            pass

    # Fallback controlado vía getnameinfo / gethostbyaddr sin tocar setdefaulttimeout
    try:
        hostname, _ = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
        return hostname.rstrip(".")
    except OSError:
        return None


def _fetch_http_status(domain: str, timeout: float = 4.0) -> int | str:
    headers = {"User-Agent": "NetDigger/1.9"}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        for method in ("HEAD", "GET"):
            req = urllib.request.Request(url, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.status
            except urllib.error.HTTPError as exc:
                if exc.code == 405 and method == "HEAD":
                    continue
                return exc.code
            except OSError:
                if method == "HEAD":
                    continue
                break
    return "N/A"


def gather_target_metadata(
    domain: str,
    engine: DNSResolverEngine,
    candidate_ip: str | None = None,
    timeout: float = 4.0,
) -> dict:
    """
    Collects target summary metadata: resolved IP, PTR hostname, and HTTP status.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    ip = candidate_ip

    if not ip:
        a_res = engine.query_record(clean_domain, "A")
        if isinstance(a_res, dict) and a_res.get("status") == "SUCCESS":
            for rec in a_res.get("records", []):
                val = str(rec.get("value", "")).strip()
                if val:
                    ip = val
                    break

    if not ip:
        try:
            ip = socket.gethostbyname(clean_domain)
        except OSError:
            ip = None

    ptr = _resolve_ptr_with_engine(ip, engine=engine) if ip else None
    http_status = _fetch_http_status(clean_domain, timeout=timeout)

    if ip and ptr:
        resolves_to = f"{ip} ({ptr})"
    elif ip:
        resolves_to = ip
    else:
        resolves_to = "N/A"

    return {
        "query": clean_domain,
        "ip": ip,
        "ptr": ptr,
        "resolves_to": resolves_to,
        "http_status": http_status,
    }
