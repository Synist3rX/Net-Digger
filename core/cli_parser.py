import argparse

SUPPORTED_RECORD_TYPES = (
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
    "SOA",
    "CAA",
    "SRV",
    "PTR",
    "HTTPS",
    "SVCB",
)
ALL_RECORD_TYPES = list(SUPPORTED_RECORD_TYPES)


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Net Digger: Advanced DNS query and reconnaissance CLI tool."
    )

    parser.add_argument(
        "domain_pos",
        nargs="?",
        metavar="DOMAIN",
        help="Target domain to query (e.g., example.com or eñe.es)",
    )

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("-d", "--domain", dest="domain_opt", help="Target single domain to query")
    source_group.add_argument("-f", "--file", help="TXT file containing a list of domains (one per line)")

    parser.add_argument(
        "-t",
        "--type",
        dest="record_type",
        nargs="?",
        const="ALL",
        default=None,
        help="DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV, PTR, HTTPS, SVCB, ALL). Defaults to ALL when -t is passed without value",
    )
    parser.add_argument(
        "-ns",
        "--nameserver",
        dest="nameserver",
        default="1.1.1.1",
        help="Target DNS nameserver IP (default: 1.1.1.1)",
    )
    parser.add_argument(
        "--tcp",
        action="store_true",
        help="Use TCP transport protocol instead of UDP for DNS queries",
    )
    parser.add_argument(
        "-to",
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds per attempt (default: 5.0)",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=3,
        help="Maximum number of automatic retries on network failure (default: 3)",
    )
    parser.add_argument(
        "-o",
        "--output",
        nargs="?",
        const="",
        default=None,
        help="Export results to JSON. Defaults to 'output/<target>.json' when passed without a filename",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Display full untruncated record values in terminal output",
    )
    parser.add_argument(
        "--ssl",
        action="store_true",
        help="Inspect TLS/SSL certificate details on port 443 for each target domain",
    )
    parser.add_argument(
        "--whois",
        action="store_true",
        help="Perform WHOIS lookup (port 43) for each target domain",
    )
    parser.add_argument(
        "--email",
        action="store_true",
        help="Audit email authentication posture (SPF, DMARC, and common DKIM selectors)",
    )
    parser.add_argument(
        "--blacklist",
        action="store_true",
        help="Check target IP and domain against common DNSBL and URIBL blacklists",
    )
    parser.add_argument(
        "--headers",
        action="store_true",
        help="Inspect HTTP status, redirect chain, security headers, and response headers",
    )
    parser.add_argument(
        "--geo",
        "--geolocation",
        dest="geolocation",
        action="store_true",
        help="Inspect IP geolocation and ASN information for the target domain",
    )
    parser.add_argument(
        "--score",
        "--security-score",
        dest="security_score",
        action="store_true",
        help="Evaluate HTTP security headers score and letter grade",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Enable all inspection modules and full output (--type ALL, --ssl, --whois, --email, --blacklist, --headers, --geolocation, --security-score and --full)",
    )

    return parser.parse_args(argv)
