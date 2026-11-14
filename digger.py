#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path
from core.resolver import DNSResolverEngine
from core.exporter import export_to_json

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Net Digger: Advanced DNS query and reconnaissance CLI tool."
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Target single domain to query (e.g., example.com)")
    group.add_argument("-f", "--file", help="TXT file containing a list of domains (one per line)")

    parser.add_argument(
        "-t", "--type",
        default="A",
        help="DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, ALL). Default: A"
    )
    parser.add_argument(
        "-ns", "--nameserver",
        help="Custom nameserver to query (e.g., 1.1.1.1 or 8.8.8.8)"
    )
    parser.add_argument(
        "-to", "--timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds (default: 5.0)"
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
                domains.append(domain)
    return domains

def main():
    args = parse_arguments()
    engine = DNSResolverEngine(nameserver=args.nameserver, timeout=args.timeout)
    
    domains = [args.domain] if args.domain else load_domains_from_file(args.file)
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] if args.type.upper() == "ALL" else [args.type]

    all_results = []

    print(f"\n[*] Starting DNS analysis for {len(domains)} domain(s)...")
    if args.nameserver:
        print(f"[*] Using custom nameserver: {args.nameserver}")
    print("-" * 50)

    for domain in domains:
        domain_results = {"domain": domain, "queries": []}
        print(f"\n[>] Target: {domain}")
        
        for r_type in record_types:
            result = engine.query_record(domain, r_type)
            domain_results["queries"].append(result)
            
            if result["status"] == "SUCCESS":
                print(f"    [+] {result['type']} records (TTL: {result['ttl']}s):")
                for item in result["data"]:
                    print(f"        -> {item}")
            else:
                print(f"    [-] [{result['type']}] {result['message']}")
                
        all_results.append(domain_results)

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
