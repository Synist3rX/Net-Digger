#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from core.resolver import DNSResolverEngine
from core.exporter import export_to_json
from core.validator import is_valid_domain, is_valid_ip
from core.detector import detect_dns_provider, detect_email_provider


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

def process_single_domain(domain: str, engine: DNSResolverEngine, record_types: list[str], full_output: bool = False) -> dict:
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
        domain_results["queries"].append(result)

        if result["status"] == "SUCCESS":
            ttl_str = f"{result['ttl']}s"
            for rec in result["records"]:
                domain_results["total_records"] += 1
                prio_str = str(rec["priority"]) if rec["priority"] is not None else ""
                table_rows.append((result["type"], rec["value"], prio_str, ttl_str))

                if result["type"] == "NS":
                    ns_values.append(rec["value"])
                elif result["type"] == "MX":
                    mx_values.append(rec["value"])

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
            executor.submit(process_single_domain, domain, engine, record_types, args.full): domain
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
