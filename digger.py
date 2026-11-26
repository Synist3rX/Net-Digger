#!/usr/bin/env python3
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tqdm import tqdm

from core.blacklist_inspector import inspect_blacklist_block
from core.cli_parser import ALL_RECORD_TYPES, SUPPORTED_RECORD_TYPES, parse_arguments
from core.detector import detect_dns_provider, detect_email_provider
from core.dns_inspector import inspect_dns_records_data
from core.dnssec_inspector import inspect_dnssec as run_dnssec_inspection
from core.email_security import inspect_email_security
from core.exporter import export_to_json, resolve_output_path
from core.formatters import (
    format_blacklist_block,
    format_dns_records_block,
    format_dnssec_block,
    format_email_security_block,
    format_geolocation_block,
    format_http_headers_block,
    format_reputation_block,
    format_robots_block,
    format_security_score_block,
    format_sitemap_block,
    format_ssl_block,
    format_target_header,
    format_whois_block,
)
from core.geo_inspector import inspect_geolocation as run_geolocation_inspection
from core.http_inspector import inspect_http_headers
from core.reputation_inspector import inspect_reputation as run_reputation_inspection
from core.resolver import DNSResolverEngine
from core.robots_inspector import inspect_robots as run_robots_inspection
from core.security_score import inspect_security_score
from core.sitemap_inspector import inspect_sitemap as run_sitemap_inspection
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
    inspect_dns_records: bool = False,
    inspect_blacklist: bool = False,
    inspect_dnssec: bool = False,
    inspect_email: bool = False,
    inspect_geolocation: bool = False,
    inspect_headers: bool = False,
    inspect_reputation: bool = False,
    inspect_robots: bool = False,
    inspect_score: bool = False,
    inspect_sitemap: bool = False,
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
    first_a_record = None

    # Sección del Target siempre visible
    target_meta = gather_target_metadata(domain, engine, candidate_ip=first_a_record, timeout=min(engine.resolver.timeout, 4.0))
    domain_results["target"] = target_meta
    output_lines = format_target_header(domain, target_meta)

    # -t / --type | Sección de DNS Records solo cuando se solicita
    if inspect_dns_records:
        dns_data = inspect_dns_records_data(domain=domain, engine=engine, record_types=record_types)

        domain_results["queries"] = dns_data["queries"]
        domain_results["total_records"] = dns_data["total_records"]
        domain_results["dns_provider"] = dns_data["dns_provider"]
        domain_results["email_provider"] = dns_data["email_provider"]
        table_rows = dns_data["table_rows"]
        first_a_record = dns_data["first_a_record"]

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

    # --ssl
    if inspect_ssl:
        ssl_info = inspect_ssl_certificate(domain, timeout=engine.resolver.timeout)
        domain_results["ssl_certificate"] = ssl_info
        output_lines.extend(format_ssl_block(ssl_info, full_output=full_output))

    # --headers
    http_headers_info = None
    if inspect_headers or inspect_score:
        http_headers_info = inspect_http_headers(target=domain, engine=engine)
        if inspect_headers:
            domain_results["http_headers"] = http_headers_info
            output_lines.extend(format_http_headers_block(http_info=http_headers_info, full_output=full_output))

    # --whois
    if inspect_whois:
        whois_info = run_whois_inspection(domain, timeout=engine.resolver.timeout)
        domain_results["whois"] = whois_info
        output_lines.extend(format_whois_block(whois_info, full_output=full_output))

    # --geo / --geolocation
    geolocation_info = None
    if inspect_geolocation or inspect_reputation:
        geolocation_info = run_geolocation_inspection(ip=target_meta.get("ip"), engine=engine)
        if inspect_geolocation:
            domain_results["geolocation"] = geolocation_info
            output_lines.extend(format_geolocation_block(geo_info=geolocation_info, full_output=full_output))

    # --reputation
    if inspect_reputation:
        reputation_info = run_reputation_inspection(ip=target_meta.get("ip"), engine=engine, geolocation_info=geolocation_info)
        domain_results["reputation"] = reputation_info
        output_lines.extend(format_reputation_block(reputation_info=reputation_info, full_output=full_output))

    # --dnssec
    if inspect_dnssec:
        dnssec_info = run_dnssec_inspection(domain=domain, engine=engine)
        domain_results["dnssec"] = dnssec_info
        output_lines.extend(format_dnssec_block(dnssec_info=dnssec_info, full_output=full_output))

    # --score / --security-score
    if inspect_score:
        security_score_info = inspect_security_score(target=domain, engine=engine, http_headers_info=http_headers_info)
        domain_results["security_score"] = security_score_info
        output_lines.extend(format_security_score_block(security_score_info=security_score_info, full_output=full_output))

    # --email
    if inspect_email:
        email_info = inspect_email_security(domain, engine)
        domain_results["email_security"] = email_info
        output_lines.extend(format_email_security_block(email_info, full_output=full_output))

    # --blacklist
    if inspect_blacklist:
        blacklist_info = inspect_blacklist_block(domain=domain, engine=engine, ip=target_meta.get("ip"))
        domain_results["blacklist"] = blacklist_info
        output_lines.extend(format_blacklist_block(blacklist_info=blacklist_info, full_output=full_output))

    # --robots
    robots_info = None
    if inspect_robots or inspect_sitemap:
        robots_info = run_robots_inspection(domain=domain, engine=engine)
        if inspect_robots:
            domain_results["robots"] = robots_info
            output_lines.extend(format_robots_block(robots_info=robots_info, full_output=full_output))

    # --sitemap
    if inspect_sitemap:
        sitemap_info = run_sitemap_inspection(domain=domain, engine=engine, robots_info=robots_info)
        domain_results["sitemap"] = sitemap_info
        output_lines.extend(format_sitemap_block(sitemap_info=sitemap_info, full_output=full_output))

    # Output Lines
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
    args.dnssec = args.dnssec or args.all
    args.email = args.email or args.all
    args.geolocation = args.geolocation or args.all
    args.headers = args.headers or args.all
    args.reputation = args.reputation or args.all
    args.robots = args.robots or args.all
    args.security_score = args.security_score or args.all
    args.sitemap = args.sitemap or args.all
    args.ssl = args.ssl or args.all
    args.whois = args.whois or args.all
    args.full = args.full or args.all

    try:
        inspect_dns_records, record_types = parse_record_types(
            args.record_type,
            include_all_flag=args.all,
        )
    except ValueError as exc:
        print(f"[!] Error: {exc}")
        sys.exit(1)

    if inspect_dns_records:
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
                domain=domain,
                engine=engine,
                record_types=record_types,
                inspect_dns_records=inspect_dns_records,
                inspect_blacklist=args.blacklist,
                inspect_dnssec=args.dnssec,
                inspect_email=args.email,
                inspect_geolocation=args.geolocation,
                inspect_headers=args.headers,
                inspect_reputation=args.reputation,
                inspect_robots=args.robots,
                inspect_score=args.security_score,
                inspect_sitemap=args.sitemap,
                inspect_ssl=args.ssl,
                inspect_whois=args.whois,
                full_output=args.full,
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
