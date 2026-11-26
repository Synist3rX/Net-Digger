import re
import socket
from datetime import datetime, timezone


EPP_STATUS_RE = re.compile(
    r"\b(client|server)(Delete|Transfer|Update|Hold|Renew)Prohibited\b",
    re.IGNORECASE,
)

DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d.%m.%Y",
    "%Y/%m/%d",
)


def _raw_whois_query(server: str, query: str, timeout: float = 5.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query.strip() + "\r\n").encode("utf-8", errors="replace"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _parse_whois_date(raw_value: str | None) -> datetime | None:
    if not raw_value:
        return None
    cleaned = raw_value.strip()
    # Normaliza sufijos como ' UTC' o ' GMT'
    cleaned = re.sub(r"\s+(UTC|GMT)$", "", cleaned, flags=re.IGNORECASE)

    # Extrae prefijo ISO si viene con zona o milisegundos extraños
    iso_match = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", cleaned)
    candidates = [cleaned]
    if iso_match:
        candidates.append(iso_match.group(1))
    date_only = re.match(r"^(\d{4}-\d{2}-\d{2})", cleaned)
    if date_only:
        candidates.append(date_only.group(1))

    for candidate in candidates:
        for fmt in DATE_FORMATS:
            try:
                dt = datetime.strptime(candidate, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
                return dt
            except ValueError:
                continue
    return None


def _format_short_date(dt: datetime | None) -> str:
    if dt is None:
        return "N/A"
    return dt.strftime("%b %d, %Y").replace(" 0", " ")


def _extract_server_ref(text: str) -> str | None:
    patterns = (
        r"(?im)^\s*Registrar WHOIS Server\s*:\s*(\S+)\s*$",
        r"(?im)^\s*WHOIS Server\s*:\s*(\S+)\s*$",
        r"(?im)^\s*refer\s*:\s*(\S+)\s*$",
    )
    for pat in patterns:
        match = re.search(pat, text)
        if match:
            host = match.group(1).strip()
            if "." in host:
                return host
    return None


def _first_match(text: str, labels: tuple[str, ...]) -> str | None:
    for label in labels:
        pattern = re.compile(rf"(?im)^\s*{re.escape(label)}\s*:\s*(.+?)\s*$")
        match = pattern.search(text)
        if match:
            val = match.group(1).strip()
            if val and val.lower() not in ("not applicable", "n/a", "none"):
                return val
    return None


def _all_matches(text: str, labels: tuple[str, ...]) -> list[str]:
    results: list[str] = []
    for label in labels:
        pattern = re.compile(rf"(?im)^\s*{re.escape(label)}\s*:\s*(.+?)\s*$")
        for match in pattern.finditer(text):
            val = match.group(1).strip()
            if val:
                results.append(val)
    return results


def _normalize_statuses(raw_statuses: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw_statuses:
        epp_match = EPP_STATUS_RE.search(item)
        code = epp_match.group(0) if epp_match else item.split()[0].strip()
        if code and code not in seen:
            seen.add(code)
            normalized.append(code)
    return normalized


def inspect_whois(domain: str, timeout: float = 5.0) -> dict:
    """
    Queries WHOIS (port 43) with referral support and returns structured domain metadata.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    tld = clean_domain.split(".")[-1] if "." in clean_domain else clean_domain

    try:
        iana_raw = _raw_whois_query("whois.iana.org", tld, timeout=timeout)
        tld_server = _extract_server_ref(iana_raw) or f"{tld}.whois-servers.net"

        raw_text = _raw_whois_query(tld_server, clean_domain, timeout=timeout)
        registrar_server = _extract_server_ref(raw_text)

        combined_text = raw_text
        if registrar_server and registrar_server.lower() != tld_server.lower():
            try:
                reg_text = _raw_whois_query(registrar_server, clean_domain, timeout=timeout)
                if reg_text.strip():
                    combined_text = f"{raw_text}\n{reg_text}"
            except OSError:
                pass
    except Exception as exc:
        return {
            "status": "ERROR",
            "domain": clean_domain.upper(),
            "message": f"WHOIS lookup failed for {clean_domain}: {exc}",
        }

    if not combined_text.strip():
        return {
            "status": "ERROR",
            "domain": clean_domain.upper(),
            "message": f"Empty WHOIS response received for {clean_domain}.",
        }

    registrar = _first_match(combined_text, ("Registrar", "Sponsoring Registrar")) or "N/A"
    registrar_url = _first_match(combined_text, ("Registrar URL", "Referral URL", "URL of the ICANN Registrar")) or "N/A"
    country = _first_match(combined_text, ("Registrant Country", "Country")) or "N/A"
    dnssec_raw = _first_match(combined_text, ("DNSSEC",)) or "unsigned"
    dnssec = "signed" if "signed" in dnssec_raw.lower() and "unsigned" not in dnssec_raw.lower() else "unsigned"

    dt_registered = _parse_whois_date(
        _first_match(combined_text, ("Creation Date", "Registered Date", "Created", "Registration Time"))
    )
    dt_updated = _parse_whois_date(
        _first_match(combined_text, ("Updated Date", "Last Updated", "Changed", "Modified"))
    )
    dt_expires = _parse_whois_date(
        _first_match(combined_text, ("Registry Expiry Date", "Registrar Registration Expiration Date", "Expiration Date", "Expires"))
    )

    now_utc = datetime.now(timezone.utc)
    years_ago = None
    if dt_registered is not None:
        years_ago = max(0, int((now_utc - dt_registered).days // 365.25))

    term_years = None
    if dt_registered is not None and dt_expires is not None:
        term_years = max(1, round((dt_expires - dt_registered).days / 365.25))

    raw_ns = _all_matches(combined_text, ("Name Server", "Nameserver", "nserver"))
    nameservers: list[str] = []
    seen_ns: set[str] = set()
    for ns in raw_ns:
        host = ns.split()[0].strip().rstrip(".").upper()
        if host and host not in seen_ns:
            seen_ns.add(host)
            nameservers.append(host)

    raw_statuses = _all_matches(combined_text, ("Domain Status", "Status"))
    statuses = _normalize_statuses(raw_statuses)

    return {
        "status": "SUCCESS",
        "domain": clean_domain.upper(),
        "registrar": registrar,
        "registrar_url": registrar_url,
        "country": country,
        "dnssec": dnssec,
        "registered": _format_short_date(dt_registered),
        "years_ago": years_ago,
        "term_years": term_years,
        "updated": _format_short_date(dt_updated),
        "expires": _format_short_date(dt_expires),
        "nameservers": nameservers,
        "statuses": statuses,
    }
