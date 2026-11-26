#!/usr/bin/env python3
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tqdm import tqdm

from core.blacklist_inspector import inspect_blacklist_block
from core.cli_parser import ALL_RECORD_TYPES, SUPPORTED_RECORD_TYPES, parse_arguments
from core.detector import detect_dns_provider, detect_email_provider
from core.email_security import inspect_email_security
from core.exporter import export_to_json, resolve_output_path
from core.formatters import (
    format_blacklist_block,
    format_dns_records_block,
    format_email_security_block,
    format_geolocation_block,
    format_http_headers_block,
    format_security_score_block,
    format_ssl_block,
    format_target_header,
    format_whois_block,
)
from core.geo_inspector import inspect_geolocation as run_geolocation_inspection
from core.http_inspector import inspect_http_headers
from core.resolver import DNSResolverEngine
from core.security_score import inspect_security_score
from core.ssl_inspector import inspect_ssl_certificate
from core.target_inspector import gather_target_metadata
from core.validator import is_valid_domain, is_valid_ip
from core.whois_inspector import inspect_whois as run_whois_inspection


SUPPORTED_RECORD_TYPES = (
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR", "HTTPS", "SVCB"
)
ALL_RECORD_TYPES = list(SUPPORTED_RECORD_TYPES)
SEPARATOR_WIDTH = 80
INTERN_SEPARATOR_WIDTH = 72
SECTION_DIVIDER = "\n" + "-" * SEPARATOR_WIDTH
INDENTED_DIVIDER = "    " + "-" * INTERN_SEPARATOR_WIDTH


def parse_record_types(raw_type: str | None, *, include_all_flag: bool = False) -> tuple[bool, list[str]]:
    """
    Determines whether DNS records should be queried/displayed and returns
    (show_dns_records, record_types). Raises ValueError on unsupported record types.
    """
    show_dns_records = (raw_type is not None) or include_all_flag
    if not show_dns_records:
        return False, []

    effective = raw_type if raw_type is not None else "ALL"
    normalized = effective.strip().upper()

    if not normalized:
        raise ValueError("Record type cannot be empty when -t/--type is specified.")

    if normalized == "ALL":
        return True, list(ALL_RECORD_TYPES)

    requested = [item.strip().upper() for item in normalized.split(",") if item.strip()]
    if not requested:
        raise ValueError("Record type cannot be empty when -t/--type is specified.")

    invalid = [rt for rt in requested if rt not in SUPPORTED_RECORD_TYPES]
    if invalid:
        supported_str = ", ".join(SUPPORTED_RECORD_TYPES)
        raise ValueError(
            f"Unsupported DNS record type(s): {', '.join(invalid)}. Supported: {supported_str}, ALL"
        )

    # Deduplica preservando orden
    deduped = list(dict.fromkeys(requested))
    return True, deduped


def load_domains_from_file(filepath: str) -> list[str]:
    path = Path(filepath)
    if not path.exists():
        print(f"[!] Error: The file '{filepath}' does not exist.")
        sys.exit(1)

    domains = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip()
            if domain and not domain.startswith("#"):
                if is_valid_domain(domain):
                    domains.append(domain)
                else:
                    tqdm.write(f"[!] Warning: Skipping invalid domain format in file: '{domain}'")
    return domains


def process_single_domain(
    domain: str,
    engine: DNSResolverEngine,
    record_types: list[str],
    show_dns_records: bool = False,
    inspect_blacklist: bool = False,
    inspect_email: bool = False,
    inspect_geolocation: bool = False,
    inspect_headers: bool = False,
    inspect_score: bool = False,
    inspect_ssl: bool = False,
    inspect_whois: bool = False,
    full_output: bool = False,
) -> dict:
    domain_results = {
        "domain": domain,
        "target": {},
        "total_records": 0,
        "dns_provider": "Unknown",
        "email_provider": "Unknown",
        "queries": [],
    }

    table_rows = []
    ns_values = []
    mx_values = []
    first_a_record = None

    if show_dns_records:
        for r_type in record_types:
            result = engine.query_record(domain, r_type)
            if not isinstance(result, dict):
                result = {
                    "status": "ERROR",
                    "type": r_type.upper(),
                    "message": "Empty response received from DNS resolver engine.",
                }

            domain_results["queries"].append(result)

            if result.get("status") == "SUCCESS":
                ttl_str = f"{result.get('ttl', 0)}s"
                for rec in result.get("records", []):
                    domain_results["total_records"] += 1
                    val = str(rec.get("value", ""))
                    prio_str = str(rec["priority"]) if rec.get("priority") is not None else ""
                    table_rows.append((result["type"], val, prio_str, ttl_str))

                    if result["type"] == "A" and not first_a_record and val.strip():
                        first_a_record = val.strip()
                    elif result["type"] == "NS":
                        ns_values.append(val)
                    elif result["type"] == "MX":
                        mx_values.append(val)

        if "NS" in [rt.upper() for rt in record_types]:
            domain_results["dns_provider"] = detect_dns_provider(ns_values)
        if "MX" in [rt.upper() for rt in record_types]:
            domain_results["email_provider"] = detect_email_provider(mx_values)

    target_meta = gather_target_metadata(
        domain,
        engine,
        candidate_ip=first_a_record,
        timeout=min(engine.resolver.timeout, 4.0),
    )
    domain_results["target"] = target_meta

    blacklist_info = None
    if inspect_blacklist:
        blacklist_info = inspect_blacklist_block(
            domain=domain,
            engine=engine,
            ip=target_meta.get("ip"),
        )
        domain_results["blacklist"] = blacklist_info
    
    http_headers_info = None
    if inspect_headers:
        http_headers_info = inspect_http_headers(
            target=domain,
            engine=engine,
        )
        domain_results["http_headers"] = http_headers_info

    geolocation_info = None
    if inspect_geolocation:
        geolocation_info = run_geolocation_inspection(
            ip=target_meta.get("ip"),
            engine=engine,
        )
        domain_results["geolocation"] = geolocation_info

    security_score_info = None
    if inspect_score:
        security_score_info = inspect_security_score(
            target=domain,
            engine=engine,
            http_headers_info=http_headers_info,
        )
        domain_results["security_score"] = security_score_info

    # Sección del target siempre visible
    output_lines = format_target_header(domain, target_meta)

    # Sección de DNS Records solo cuando se solicita -t / --type o --all
    if show_dns_records:
        output_lines.extend(
            format_dns_records_block(
                table_rows=table_rows,
                total_records=domain_results["total_records"],
                record_types=record_types,
                dns_provider=domain_results["dns_provider"],
                email_provider=domain_results["email_provider"],
                full_output=full_output,
            )
        )

    if inspect_ssl:
        ssl_info = inspect_ssl_certificate(domain, timeout=engine.resolver.timeout)
        domain_results["ssl_certificate"] = ssl_info
        output_lines.extend(format_ssl_block(ssl_info, full_output=full_output))

    if inspect_whois:
        whois_info = run_whois_inspection(domain, timeout=engine.resolver.timeout)
        domain_results["whois"] = whois_info
        output_lines.extend(format_whois_block(whois_info, full_output=full_output))

    if inspect_email:
        email_info = inspect_email_security(domain, engine)
        domain_results["email_security"] = email_info
        output_lines.extend(format_email_security_block(email_info, full_output=full_output))

    if inspect_blacklist:
        output_lines.extend(
            format_blacklist_block(
                blacklist_info=blacklist_info,
                full_output=full_output,
            )
        )

    if inspect_headers:
        output_lines.extend(
            format_http_headers_block(
                http_info=http_headers_info,
                full_output=full_output,
            )
        )

    if inspect_geolocation:
        output_lines.extend(
            format_geolocation_block(
                geo_info=geolocation_info,
                full_output=full_output,
            )
        )

    if inspect_score:
        output_lines.extend(
            format_security_score_block(
                security_score_info=security_score_info,
                full_output=full_output,
            )
        )

    output_lines.append("\n" + "-"*80)
    tqdm.write("\n".join(output_lines))
    return domain_results


def main():
    args = parse_arguments()

    if args.nameserver and not is_valid_ip(args.nameserver):
        print(f"[!] Error: Invalid nameserver IP address format: '{args.nameserver}'")
        sys.exit(1)

    if args.domain_opt and args.domain_pos:
        print("[!] Error: Provide the target domain either positionally or via -d/--domain, not both.")
        sys.exit(1)

    single_domain = args.domain_opt or args.domain_pos

    if single_domain:
        if not is_valid_domain(single_domain):
            print(f"[!] Error: Invalid domain format: '{single_domain}'")
            sys.exit(1)
        domains = [single_domain]
    elif args.file:
        domains = load_domains_from_file(args.file)
        if not domains:
            print("[!] Error: No valid domains found in the specified file.")
            sys.exit(1)
    else:
        print("[!] Error: You must specify a target domain or a file (-f/--file).")
        sys.exit(1)

    args.blacklist = args.blacklist or args.all
    args.email = args.email or args.all
    args.geolocation = args.geolocation or args.all
    args.headers = args.headers or args.all
    args.security_score = args.security_score or args.all
    args.ssl = args.ssl or args.all
    args.whois = args.whois or args.all
    args.full = args.full or args.all

    try:
        show_dns_records, record_types = parse_record_types(
            args.record_type,
            include_all_flag=args.all,
        )
    except ValueError as exc:
        print(f"[!] Error: {exc}")
        sys.exit(1)

    if show_dns_records:
        effective_type = args.record_type if args.record_type is not None else "ALL"
        if effective_type.upper() == "ALL":
            record_types = ALL_RECORD_TYPES
        else:
            record_types = [rt.strip().upper() for rt in effective_type.split(",") if rt.strip()]
    else:
        record_types = []

    engine = DNSResolverEngine(
        nameserver=args.nameserver,
        timeout=args.timeout,
        retries=args.retries,
        use_tcp=args.tcp,
    )

    all_results = []
    max_workers = min(10, len(domains)) if domains else 1

    transport_mode = "TCP" if args.tcp else "UDP"
    print(f"\n[*] Starting concurrent DNS analysis for {len(domains)} domain(s) using {max_workers} thread(s)...")
    print(f"[*] Transport Protocol: {transport_mode}")
    if args.nameserver:
        print(f"[*] Using custom nameserver: {args.nameserver}")
    print(f"[*] Retry policy: {args.retries} attempts with exponential backoff.")
    print("-" * 50)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(
                process_single_domain,
                domain,
                engine,
                record_types,
                show_dns_records,
                args.blacklist,
                args.email,
                args.geolocation,
                args.headers,
                args.security_score,
                args.ssl,
                args.whois,
                args.full,
            ): domain
            for domain in domains
        }

        with tqdm(total=len(domains), desc="Progress", unit="domain", dynamic_ncols=True) as pbar:
            for future in as_completed(future_to_domain):
                try:
                    domain_results = future.result()
                    all_results.append(domain_results)
                except Exception as e:
                    tqdm.write(f"[!] Error processing domain: {e}")
                finally:
                    pbar.update(1)

    print("-" * 50)

    if args.output is not None:
        output_path = resolve_output_path(args.output, domains)
        success, message = export_to_json(all_results, str(output_path))
        if success:
            print(f"\n[✔] {message}")
        else:
            print(f"\n[✖] {message}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")
        sys.exit(0)
