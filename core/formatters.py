SEPARATOR_WIDTH = 80
INTERN_SEPARATOR_WIDTH = 72
SECTION_DIVIDER = "\n" + "-" * SEPARATOR_WIDTH
INDENTED_DIVIDER = "    " + "-" * INTERN_SEPARATOR_WIDTH


def format_target_header(domain: str, target_meta: dict) -> list[str]:
    return [
        f"\n[>] Target: {domain}",
        f"    {'Query':<16}: {target_meta.get('query', domain)}",
        f"    {'Resolves To':<16}: {target_meta.get('resolves_to', 'N/A')}",
        f"    {'HTTP Status':<16}: {target_meta.get('http_status', 'N/A')}",
    ]


def format_dns_records_block(
    table_rows: list[tuple[str, str, str, str]],
    total_records: int,
    record_types: list[str],
    dns_provider: str = "Unknown",
    email_provider: str = "Unknown",
    full_output: bool = False,
) -> list[str]:
    lines = [
        SECTION_DIVIDER,
        f"[>] DNS Records ({total_records} records found)",
    ]

    if table_rows:
        lines.append(INDENTED_DIVIDER)
        lines.append(f"    {'TYPE':<8} {'PRIO':<6} {'TTL':<8} {'VALUE'}")
        lines.append(INDENTED_DIVIDER)
        for r_type, val, prio, ttl in table_rows:
            prio_display = prio if prio else "-"
            if full_output or len(val) <= INTERN_SEPARATOR_WIDTH:
                display_val = val
            else:
                display_val = val[:INTERN_SEPARATOR_WIDTH-3] + "..."
            lines.append(f"    {r_type:<8} {prio_display:<6} {ttl:<8} {display_val}")
    else:
        lines.append("    [-] No DNS records retrieved for the requested type(s).")

    lines.append(INDENTED_DIVIDER)
    upper_types = {rt.upper() for rt in record_types}
    if "NS" in upper_types:
        lines.append(f"    [*] DNS Provider   : {dns_provider} (detected via NS)")
    if "MX" in upper_types:
        lines.append(f"    [*] Email Provider : {email_provider} (detected via MX)")
    lines.append(INDENTED_DIVIDER)

    return lines


def format_ssl_block(ssl_info: dict, full_output: bool = False) -> list[str]:
    lines = [SECTION_DIVIDER, "[>] SSL Certificate"]

    if not isinstance(ssl_info, dict):
        lines.append("    [-] SSL inspection returned no data (None).")
        return lines

    if ssl_info.get("status") != "SUCCESS":
        lines.append(f"    [-] {ssl_info.get('message', 'Unknown SSL error')}")
        return lines

    days = ssl_info["days_remaining"]
    badge = f"{days}d left" if days is not None else "N/A"
    covered_str = "Yes" if ssl_info["domain_included"] else "No"
    self_signed_str = "Yes" if ssl_info["is_self_signed"] else "No"

    lines.append(f"    {'Status':<16}: {badge} (TLS: {ssl_info.get('tls_version') or 'N/A'})")
    lines.append(f"    {'Common Name':<16}: {ssl_info['common_name']}")
    lines.append(f"    {'Issuer':<16}: {ssl_info['issuer']}")
    lines.append(f"    {'Valid From':<16}: {ssl_info['valid_from']}")
    lines.append(f"    {'Expires':<16}: {ssl_info['expires']}")
    lines.append(f"    {'Days Remaining':<16}: {days if days is not None else 'N/A'}")
    lines.append(f"    {'Domain Included':<16}: {covered_str}")
    lines.append(f"    {'Self-Signed':<16}: {self_signed_str}")

    sans = ssl_info.get("sans", [])
    if sans:
        if full_output or len(sans) <= 6:
            sans_display = " ".join(sans)
        else:
            preview = " ".join(sans[:6])
            remaining = len(sans) - 6
            sans_display = f"{preview} +{remaining} more"
        label = f"SANs ({len(sans)})"
        lines.append(f"    {label:<16}: {sans_display}")
    else:
        lines.append(f"    {'SANs (0)':<16}: None")

    return lines


def format_whois_block(whois_info: dict | None, full_output: bool = False) -> list[str]:
    lines = [SECTION_DIVIDER, "[>] WHOIS"]

    if not isinstance(whois_info, dict):
        lines.append("    [-] WHOIS inspection returned no data.")
        return lines

    if whois_info.get("status") != "SUCCESS":
        lines.append(f"    [-] {whois_info.get('message', 'Unknown WHOIS error')}")
        return lines

    years_ago = whois_info.get("years_ago")
    registered_str = whois_info.get("registered", "N/A")
    if years_ago is not None and registered_str != "N/A":
        registered_str = f"{registered_str} ({years_ago} years ago)"

    term_years = whois_info.get("term_years")
    term_str = f"{term_years} years" if term_years is not None else "N/A"

    ns_list = whois_info.get("nameservers", [])
    ns_str = " ".join(ns_list) if ns_list else "None"

    statuses = whois_info.get("statuses", [])
    if statuses:
        if full_output or len(statuses) <= 6:
            status_str = ", ".join(statuses)
        else:
            status_str = ", ".join(statuses[:6]) + f" +{len(statuses) - 6} more"
    else:
        status_str = "None"

    lines.append(f"    {'Domain':<16}: {whois_info.get('domain', 'N/A')}")
    lines.append(f"    {'Registrar':<16}: {whois_info.get('registrar', 'N/A')}")
    lines.append(f"    {'Registrar URL':<16}: {whois_info.get('registrar_url', 'N/A')}")
    lines.append(f"    {'Country':<16}: {whois_info.get('country', 'N/A')}")
    lines.append(f"    {'DNSSEC':<16}: {whois_info.get('dnssec', 'unsigned')}")
    lines.append(f"    {'Registered':<16}: {registered_str}")
    lines.append(f"    {'Term':<16}: {term_str}")
    lines.append(f"    {'Updated':<16}: {whois_info.get('updated', 'N/A')}")
    lines.append(f"    {'Expires':<16}: {whois_info.get('expires', 'N/A')}")
    lines.append(f"    {'Nameservers':<16}: {ns_str}")
    lines.append(f"    {'Status':<16}: {status_str}")

    return lines


def format_email_security_block(email_info: dict | None, full_output: bool = False) -> list[str]:
    lines = [SECTION_DIVIDER, "[>] Email Security"]

    if not isinstance(email_info, dict):
        lines.append("    [-] Email security inspection returned no data.")
        return lines

    if email_info.get("status") != "SUCCESS":
        lines.append(f"    [-] {email_info.get('message', 'Unknown email security error')}")
        return lines

    lines.append(f"    {'Overall':<16}: {email_info.get('overall_status', 'Partial')}")

    spf = email_info.get("spf", {})
    spf_status = spf.get("status", "Missing")
    spf_lookups = f"{spf.get('lookups', 0)}/{spf.get('max_lookups', 10)} lookups"
    lines.append(f"    {'SPF':<16}: {spf_status} ({spf_lookups})")
    if spf.get("record"):
        rec = spf["record"]
        if not full_output and len(rec) > INTERN_SEPARATOR_WIDTH:
            rec = rec[:INTERN_SEPARATOR_WIDTH-3] + "..."
        lines.append(f"    {'SPF Record':<16}: {rec}")

    dmarc = email_info.get("dmarc", {})
    if dmarc.get("found"):
        pol = dmarc.get("policy", "none")
        reports = f"Reports: {dmarc['reports']}" if dmarc.get("reports") else "Reports: None"
        lines.append(f"    {'DMARC':<16}: {pol} ({reports})")
        if dmarc.get("record"):
            drec = dmarc["record"]
            if not full_output and len(drec) > INTERN_SEPARATOR_WIDTH:
                drec = drec[:INTERN_SEPARATOR_WIDTH-3] + "..."
            lines.append(f"    {'DMARC Record':<16}: {drec}")
    else:
        lines.append(f"    {'DMARC':<16}: Missing")

    dkim = email_info.get("dkim", {})
    dkim_status = dkim.get("status", "Not detected")
    dkim_detail = dkim.get("detail", "No selectors found from common list")
    lines.append(f"    {'DKIM':<16}: {dkim_status} ({dkim_detail})")

    return lines


def format_blacklist_block(
    blacklist_info: dict | None,
    full_output: bool = False,
) -> list[str]:
    lines = [SECTION_DIVIDER, "[>] Blacklist Check"]

    if not isinstance(blacklist_info, dict):
        lines.append("    [-] Blacklist inspection returned no data.")
        return lines

    if blacklist_info.get("status") != "SUCCESS":
        lines.append(f"    [-] {blacklist_info.get('message', 'Unknown blacklist error')}")
        return lines

    overall = blacklist_info.get("overall_status", "Clean")
    checked_ip = blacklist_info.get("checked_ip", "N/A")
    clean_count = blacklist_info.get("clean_count", 0)
    listed_count = blacklist_info.get("listed_count", 0)
    error_count = blacklist_info.get("error_count", 0)
    total_checked = blacklist_info.get("total_checked", 0)

    lines.append(f"    {'Overall':<16}: {overall}")
    lines.append(f"    {'Checked IP':<16}: {checked_ip}")

    summary_parts = [f"Clean: {clean_count}/{total_checked}"]
    if listed_count > 0:
        summary_parts.append(f"Listed: {listed_count}")
    if error_count > 0:
        summary_parts.append(f"Errors: {error_count}")
    lines.append(f"    {'Summary':<16}: " + " | ".join(summary_parts))

    checks = blacklist_info.get("checks") or []
    notable_checks = [c for c in checks if c.get("status") in {"Listed", "Error"}]

    lines.append(INDENTED_DIVIDER)
    lines.append(f"    {'PROVIDER':<22} {'SCOPE':<8} {'STATUS':<8} {'DETAIL'}")
    lines.append(INDENTED_DIVIDER)

    if full_output and checks:
        for item in checks:
            name = str(item.get("name", "Unknown"))[:22]
            scope = str(item.get("scope", "ip"))[:8]
            status = str(item.get("status", "Clean"))[:8]
            if status == "Listed":
                detail = str(item.get("response") or "Listed")
            elif status == "Error":
                detail = str(item.get("message") or "Query error")
            elif status == "Skipped":
                detail = str(item.get("message") or "Skipped")
            else:
                detail = "OK"
            lines.append(f"    {name:<22} {scope:<8} {status:<8} {detail}")
    elif notable_checks:
        for item in notable_checks:
            name = str(item.get("name", "Unknown"))[:22]
            scope = str(item.get("scope", "ip"))[:8]
            status = str(item.get("status", "Listed"))[:8]
            detail = str(item.get("response") or item.get("message") or status)
            lines.append(f"    {name:<22} {scope:<8} {status:<8} {detail}")

    lines.append(INDENTED_DIVIDER)

    return lines


def format_http_headers_block(
    http_info: dict | None,
    full_output: bool = False,
) -> list[str]:
    lines = [SECTION_DIVIDER, "[>] HTTP & Headers"]

    if not isinstance(http_info, dict):
        lines.append("    [-] HTTP inspection returned no data.")
        return lines

    if http_info.get("status") != "SUCCESS":
        lines.append(f"    [-] {http_info.get('message', 'Unknown HTTP error')}")
        return lines

    status_code = http_info.get("status_code", "N/A")
    final_url = http_info.get("final_url", "N/A")
    lines.append(f"    {'Status':<16}: {status_code}")
    lines.append(f"    {'Final URL':<16}: {final_url}")

    chain = http_info.get("redirect_chain") or []
    if chain:
        formatted_hops = " -> ".join(
            f"{hop.get('status_code')} {hop.get('url')}" for hop in chain
        )
        lines.append(f"    {'Redirect Chain':<16}: {formatted_hops}")

    sec = http_info.get("security_headers") or {}
    present_cnt = sec.get("present_count", 0)
    total_cnt = sec.get("total_count", 7)
    sec_items = sec.get("items") or []

    lines.append(INDENTED_DIVIDER)
    lines.append(f"    {'Security Headers':<16}: {present_cnt}/{total_cnt}")
    lines.append(INDENTED_DIVIDER)
    for item in sec_items:
        name = str(item.get("name", ""))
        if item.get("present"):
            val_display = str(item.get("value", ""))
            if not full_output and len(val_display) > 42:
                val_display = val_display[:39] + "..."
            lines.append(f"        [✔] {name:<28} {val_display}")
        else:
            lines.append(f"        [✖] {name:<28} not set")

    all_headers = http_info.get("all_headers") or {}
    if full_output and all_headers:
        lines.append(INDENTED_DIVIDER)
        lines.append(f"    {'All Headers':<16}: ({len(all_headers)})")
        lines.append(INDENTED_DIVIDER)
        for key, val in all_headers.items():
            lines.append(f"        {key}: {val}")

    return lines


def format_geolocation_block(
    geo_info: dict | None,
    full_output: bool = False,
) -> list[str]:
    lines = [SECTION_DIVIDER, "[>] Geolocation & ASN"]

    if not isinstance(geo_info, dict):
        lines.append("    [-] Geolocation inspection returned no data.")
        return lines

    status = geo_info.get("status")
    if status == "SKIPPED":
        lines.append(f"    [*] {geo_info.get('message', 'Geolocation lookup skipped.')}")
        return lines

    if status != "SUCCESS":
        lines.append(f"    [-] {geo_info.get('message', 'Unknown geolocation error')}")
        return lines

    lines.append(f"    {'IP Address':<16}: {geo_info.get('ip', 'N/A')}")
    lines.append(f"    {'Location':<16}: {geo_info.get('location', 'Unknown')}")
    if full_output and geo_info.get("country") not in {"Unknown", None}:
        lines.append(f"    {'Country':<16}: {geo_info.get('country')} ({geo_info.get('country_code', 'N/A')})")
    lines.append(f"    {'Timezone':<16}: {geo_info.get('timezone', 'Unknown')}")
    lines.append(f"    {'Coordinates':<16}: {geo_info.get('coordinates', 'N/A')}")
    lines.append(f"    {'ASN':<16}: {geo_info.get('asn', 'Unknown')}")
    lines.append(f"    {'Organization':<16}: {geo_info.get('organization', 'Unknown')}")
    lines.append(f"    {'ISP / Org':<16}: {geo_info.get('isp_org', 'Unknown')}")

    return lines


def format_security_score_block(
    security_score_info: dict | None,
    full_output: bool = False,
) -> list[str]:
    lines = [SECTION_DIVIDER, "[>] Security Score"]

    if not isinstance(security_score_info, dict):
        lines.append("    [-] Security score returned no data.")
        return lines

    if security_score_info.get("status") != "SUCCESS":
        lines.append(f"    [-] {security_score_info.get('message', 'Unknown security score error')}")
        return lines

    grade = security_score_info.get("grade", "F")
    score = security_score_info.get("score", 0)
    max_score = security_score_info.get("max_score", 95)
    category = security_score_info.get("category", "HTTP Security Headers")

    lines.append(f"    {'Grade':<16}: {grade}")
    lines.append(f"    {'Category':<16}: {category}")
    lines.append(f"    {'Points':<16}: {score} / {max_score} points")

    checks = security_score_info.get("checks") or []
    if checks:
        lines.append(INDENTED_DIVIDER)
        for item in checks:
            present = bool(item.get("present"))
            mark = "[✔]" if present else "[✖]"
            label = str(item.get("label", ""))
            pts = item.get("points", 0)
            max_pts = item.get("max_points", 0)
            status_text = str(item.get("status_text", ""))
            if not full_output and len(status_text) > 44:
                status_text = status_text[:41] + "..."
            lines.append(f"        {mark} {label:<22} {status_text:<44} {pts}/{max_pts}")

    return lines
