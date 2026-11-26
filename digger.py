#!/usr/bin/env python3
import sys
import ssl
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from core.resolver import DNSResolverEngine
from core.exporter import export_to_json
from core.validator import is_valid_domain, is_valid_ip
from core.detector import detect_dns_provider, detect_email_provider
from core.ssl_inspector import inspect_ssl_certificate
from core.whois_inspector import inspect_whois


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Net Digger: Advanced DNS query and reconnaissance CLI tool."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Target single domain to query (e.g., example.com or eñe.es)")
    group.add_argument("-f", "--file", help="TXT file containing a list of domains (one per line)")

    parser.add_argument(
        "-t", "--type",
        default="A",
        help="DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV, ALL). Default: A"
    )
    parser.add_argument(
        "-ns", "--nameserver",
        help="Custom nameserver IP to query (e.g., 1.1.1.1 or 8.8.8.8)"
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
        "--all",
        action="store_true",
        help="Enable all inspection modules and full output (--ssl, --whois, and --full)"
    )

    return parser.parse_args()

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

def format_ssl_block(ssl_info: dict, full_output: bool = False) -> list[str]:
    lines = ["\n" + "-" * 76, "[>] SSL Certificate"]

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

    lines.append(f"    Status          : {badge} (TLS: {ssl_info.get('tls_version') or 'N/A'})")
    lines.append(f"    Common Name     : {ssl_info['common_name']}")
    lines.append(f"    Issuer          : {ssl_info['issuer']}")
    lines.append(f"    Valid From      : {ssl_info['valid_from']}")
    lines.append(f"    Expires         : {ssl_info['expires']}")
    lines.append(f"    Days Remaining  : {days if days is not None else 'N/A'}")
    lines.append(f"    Domain Included : {covered_str}")
    lines.append(f"    Self-Signed     : {self_signed_str}")

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
    lines = ["\n" + "-" * 76, "[>] WHOIS"]

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

def process_single_domain(domain: str, engine: DNSResolverEngine, record_types: list[str], full_output: bool = False,
                          inspect_ssl: bool = False, inspect_whois_flag: bool = False) -> dict:
    domain_results = {
        "domain": domain,
        "total_records": 0,
        "dns_provider": "Unknown",
        "email_provider": "Unknown",
        "queries": []
    }

    table_rows = []
    ns_values = []
    mx_values = []

    for r_type in record_types:
        result = engine.query_record(domain, r_type)
        if not isinstance(result, dict):
            result = {
                "status": "ERROR",
                "type": r_type.upper(),
                "message": "Empty response received from DNS resolver engine."
            }

        domain_results["queries"].append(result)

        if result.get("status") == "SUCCESS":
            ttl_str = f"{result.get('ttl', 0)}s"
            for rec in result.get("records", []):
                domain_results["total_records"] += 1
                prio_str = str(rec["priority"]) if rec.get("priority") is not None else ""
                table_rows.append((result["type"], rec.get("value", ""), prio_str, ttl_str))

                if result["type"] == "NS":
                    ns_values.append(rec.get("value", ""))
                elif result["type"] == "MX":
                    mx_values.append(rec.get("value", ""))

    # Inferir proveedores si se consultaron NS o MX
    if "NS" in [rt.upper() for rt in record_types]:
        domain_results["dns_provider"] = detect_dns_provider(ns_values)
    if "MX" in [rt.upper() for rt in record_types]:
        domain_results["email_provider"] = detect_email_provider(mx_values)

    # Renderizado limpio estilo tabla en terminal
    output_lines = [f"\n[>] Target: {domain} ({domain_results['total_records']} records found)"]

    if table_rows:
        output_lines.append(f"    {'TYPE':<8} {'PRIO':<6} {'TTL':<8} {'VALUE'}")
        output_lines.append("    " + "-" * 72)
        for r_type, val, prio, ttl in table_rows:
            prio_display = prio if prio else "-"
            if full_output or len(val) <= 60:
                display_val = val
            else:
                display_val = val[:57] + "..."
            output_lines.append(f"    {r_type:<8} {prio_display:<6} {ttl:<8} {display_val}")
    else:
        output_lines.append("    [-] No DNS records retrieved for the requested type(s).")

    output_lines.append("    " + "-" * 70)
    if "NS" in [rt.upper() for rt in record_types]:
        output_lines.append(f"    [*] DNS Provider   : {domain_results['dns_provider']} (detected via NS)")
    if "MX" in [rt.upper() for rt in record_types]:
        output_lines.append(f"    [*] Email Provider : {domain_results['email_provider']} (detected via MX)")

    if inspect_ssl:
        ssl_info = inspect_ssl_certificate(domain, timeout=engine.resolver.timeout)
        domain_results["ssl_certificate"] = ssl_info
        output_lines.extend(format_ssl_block(ssl_info, full_output=full_output))

    if inspect_whois_flag:
        whois_info = inspect_whois(domain, timeout=engine.resolver.timeout)
        domain_results["whois"] = whois_info
        output_lines.extend(format_whois_block(whois_info, full_output=full_output))

    tqdm.write("\n".join(output_lines))
    return domain_results


def main():
    args = parse_arguments()

    if args.nameserver and not is_valid_ip(args.nameserver):
        print(f"[!] Error: Invalid nameserver IP address format: '{args.nameserver}'")
        sys.exit(1)

    if args.domain:
        if not is_valid_domain(args.domain):
            print(f"[!] Error: Invalid domain format: '{args.domain}'")
            sys.exit(1)
        domains = [args.domain]
    else:
        domains = load_domains_from_file(args.file)
        if not domains:
            print("[!] Error: No valid domains found in the specified file.")
            sys.exit(1)

    args.ssl = args.ssl or args.all
    args.whois = args.whois or args.all
    args.full = args.full or args.all

    # Inicializamos el motor pasando el parámetro use_tcp
    engine = DNSResolverEngine(
        nameserver=args.nameserver, 
        timeout=args.timeout, 
        retries=args.retries,
        use_tcp=args.tcp
    )

    record_types = [
        "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR", "HTTPS", "SVCB"
    ] if args.type.upper() == "ALL" else [args.type]

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
                args.full,
                args.ssl,
                args.whois,
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
