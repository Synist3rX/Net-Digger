#!/usr/bin/env python3
import argparse
import socket
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tqdm import tqdm

from core.detector import detect_dns_provider, detect_email_provider
from core.email_security import inspect_email_security
from core.exporter import export_to_json
from core.formatters import (
    format_dns_records_block,
    format_email_security_block,
    format_ssl_block,
    format_target_header,
    format_whois_block,
)
from core.resolver import DNSResolverEngine
from core.ssl_inspector import inspect_ssl_certificate
from core.target_inspector import gather_target_metadata
from core.validator import is_valid_domain, is_valid_ip
from core.whois_inspector import inspect_whois


SUPPORTED_RECORD_TYPES = (
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR", "HTTPS", "SVCB"
)
ALL_RECORD_TYPES = list(SUPPORTED_RECORD_TYPES)
SEPARATOR_WIDTH = 80
INTERN_SEPARATOR_WIDTH = 72
SECTION_DIVIDER = "\n" + "-" * SEPARATOR_WIDTH
INDENTED_DIVIDER = "    " + "-" * INTERN_SEPARATOR_WIDTH


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Net Digger: Advanced DNS query and reconnaissance CLI tool."
    )

    parser.add_argument(
        "domain_pos",
        nargs="?",
        metavar="DOMAIN",
        help="Target domain to query (e.g., example.com or eñe.es)"
    )

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("-d", "--domain", dest="domain_opt", help="Target single domain to query")
    source_group.add_argument("-f", "--file", help="TXT file containing a list of domains (one per line)")

    parser.add_argument(
        "-t", "--type",
        dest="record_type",
        nargs="?",
        const="ALL",
        default=None,
        help="DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV, PTR, HTTPS, SVCB, ALL). Defaults to ALL when -t is passed without value"
    )
    parser.add_argument(
        "-ns",
        "--nameserver",
        dest="nameserver",
        default="1.1.1.1",
        help="Target DNS nameserver IP (default: 1.1.1.1)"
    )
    parser.add_argument(
        "--tcp",
        action="store_true",
        help="Use TCP transport protocol instead of UDP for DNS queries"
    )
    parser.add_argument(
        "-to", "--timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds per attempt (default: 5.0)"
    )
    parser.add_argument(
        "-r", "--retries",
        type=int,
        default=3,
        help="Maximum number of automatic retries on network failure (default: 3)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to the JSON output file (e.g., results.json)"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Display full untruncated record values in terminal output"
    )
    parser.add_argument(
        "--ssl",
        action="store_true",
        help="Inspect TLS/SSL certificate details on port 443 for each target domain"
    )
    parser.add_argument(
        "--whois",
        action="store_true",
        help="Perform WHOIS lookup (port 43) for each target domain"
    )
    parser.add_argument(
        "--email",
        action="store_true",
        help="Audit email authentication posture (SPF, DMARC, and common DKIM selectors)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Enable all inspection modules and full output (--ssl, --whois, --email, and --full)"
    )

    return parser.parse_args()


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
    full_output: bool = False,
    inspect_ssl: bool = False,
    inspect_whois_flag: bool = False,
    inspect_email: bool = False,
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

    if inspect_whois_flag:
        whois_info = inspect_whois(domain, timeout=engine.resolver.timeout)
        domain_results["whois"] = whois_info
        output_lines.extend(format_whois_block(whois_info, full_output=full_output))

    if inspect_email:
        email_info = inspect_email_security(domain, engine)
        domain_results["email_security"] = email_info
        output_lines.extend(format_email_security_block(email_info, full_output=full_output))

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

    args.ssl = args.ssl or args.all
    args.whois = args.whois or args.all
    args.email = args.email or args.all
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
                args.full,
                args.ssl,
                args.whois,
                args.email,
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

    if args.output:
        success, message = export_to_json(all_results, args.output)
        if success:
            print(f"[✔] {message}")
        else:
            print(f"[✖] {message}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")
        sys.exit(0)
