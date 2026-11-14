import time
import dns.resolver
import dns.exception
from core.validator import encode_idn

class DNSResolverEngine:
    def __init__(self, nameserver: str = None, timeout: float = 5.0, retries: int = 3):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.retries = retries
        if nameserver:
            self.resolver.nameservers = [nameserver]

    def query_record(self, domain: str, record_type: str) -> dict:
        """
        Performs a robust DNS query with automatic retries and exponential backoff.
        """
        r_type = record_type.upper()
        target_domain = encode_idn(domain)
        
        attempt = 0
        while attempt < self.retries:
            try:
                answers = self.resolver.resolve(target_domain, r_type)
                results = [str(rdata) for rdata in answers]
                return {
                    "status": "SUCCESS",
                    "domain": domain,
                    "punycode": target_domain if target_domain != domain else None,
                    "type": r_type,
                    "data": results,
                    "ttl": answers.rrset.ttl
                }
            except dns.resolver.NXDOMAIN:
                # NXDOMAIN is definitive; do not retry non-existent domains
                return {
                    "status": "ERROR",
                    "type": r_type,
                    "message": f"Domain '{domain}' does not exist (NXDOMAIN)."
                }
            except dns.resolver.NoAnswer:
                # NoAnswer is definitive for this record type; do not retry
                return {
                    "status": "ERROR",
                    "type": r_type,
                    "message": f"No {r_type} records found for {domain}."
                }
            except (dns.exception.Timeout, dns.resolver.NoNameservers, Exception) as e:
                attempt += 1
                if attempt >= self.retries:
                    return {
                        "status": "ERROR",
                        "type": r_type,
                        "message": f"DNS query failed after {self.retries} attempts. Last error: {str(e)}"
                    }
                
                # Exponential backoff calculation: 1s, 2s, 4s...
                sleep_time = 2 ** (attempt - 1)
                time.sleep(sleep_time)
