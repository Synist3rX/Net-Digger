#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from core.resolver import DNSResolverEngine
from core.exporter import export_to_json
from core.validator import is_valid_domain, is_valid_ip

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

def process_single_domain(domain: str, engine: DNSResolverEngine, record_types: list[str]) -> dict:
    domain_results = {"domain": domain, "queries": []}
    tqdm.write(f"\n[>] Target: {domain}")
    
    for r_type in record_types:
        result = engine.query_record(domain, r_type)
        domain_results["queries"].append(result)
        
        if result["status"] == "SUCCESS":
            puny_info = f" (Punycode: {result['punycode']})" if result.get('punycode') else ""
            tqdm.write(f"    [+] {result['type']} records{puny_info} (TTL: {result['ttl']}s):")
            for item in result["data"]:
                tqdm.write(f"        -> {item}")
        else:
            tqdm.write(f"    [-] [{result['type']}] {result['message']}")
            
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
        "A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SRV", "SOA"
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
            executor.submit(process_single_domain, domain, engine, record_types): domain 
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
