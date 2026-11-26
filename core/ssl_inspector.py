import fnmatch
import socket
import ssl
from datetime import datetime, timezone


def _extract_name_field(rdn_sequence, oid_keys: tuple[str, ...]) -> str | None:
    if not rdn_sequence:
        return None
    for rdn in rdn_sequence:
        for attr_type, attr_value in rdn:
            if attr_type in oid_keys:
                return str(attr_value)
    return None


def _is_domain_covered(domain: str, common_name: str | None, sans: list[str]) -> bool:
    candidates = [d.lower().rstrip(".") for d in sans if d]
    if common_name:
        candidates.append(common_name.lower().rstrip("."))

    target = domain.lower().rstrip(".")
    for entry in candidates:
        if entry == target:
            return True
        if entry.startswith("*.") and fnmatch.fnmatchcase(target, entry):
            if target.count(".") == entry.count("."):
                return True
    return False


def _format_cert_date(date_str: str | None) -> tuple[str, datetime | None]:
    if not date_str:
        return "N/A", None

    formats = (
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y",
        "%Y%m%d%H%M%SZ",
    )
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            formatted = dt.strftime("%b %d, %Y").replace(" 0", " ")
            return formatted, dt
        except ValueError:
            continue

    return date_str, None


def inspect_ssl_certificate(domain: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Connects via TLS (with SNI) to extract X.509 certificate metadata and SANs.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_OPTIONAL

    cert = None
    cipher = None
    protocol = None

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
    except Exception as exc:
        return {
            "status": "ERROR",
            "domain": domain,
            "port": port,
            "message": f"SSL/TLS inspection failed on {domain}:{port}: {exc}",
        }

    if not cert:
        return {
            "status": "ERROR",
            "domain": domain,
            "port": port,
            "message": "Peer did not return a structured certificate.",
        }

    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())

    common_name = _extract_name_field(subject, ("commonName",))
    issuer_name = (
        _extract_name_field(issuer, ("organizationName",))
        or _extract_name_field(issuer, ("commonName",))
        or "Unknown"
    )

    sans = [
        value
        for ext_type, value in cert.get("subjectAltName", ())
        if ext_type.upper() == "DNS"
    ]
    if not common_name and sans:
        common_name = sans[0]

    valid_from_fmt, dt_from = _format_cert_date(cert.get("notBefore"))
    expires_fmt, dt_exp = _format_cert_date(cert.get("notAfter"))

    days_remaining = None
    expired = None
    if dt_exp is not None:
        now_utc = datetime.now(timezone.utc)
        days_remaining = (dt_exp - now_utc).days
        expired = days_remaining < 0

    is_self_signed = bool(subject and issuer and subject == issuer)
    domain_included = _is_domain_covered(domain, common_name, sans)

    return {
        "status": "SUCCESS",
        "domain": domain,
        "port": port,
        "common_name": common_name or "N/A",
        "issuer": issuer_name,
        "valid_from": valid_from_fmt,
        "expires": expires_fmt,
        "days_remaining": days_remaining,
        "expired": expired,
        "domain_included": domain_included,
        "is_self_signed": is_self_signed,
        "sans": sans,
        "sans_count": len(sans),
        "tls_version": protocol,
        "cipher": cipher[0] if cipher else None,
    }
