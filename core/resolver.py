import time
import dns.resolver
import dns.exception
from core.validator import encode_idn

class DNSResolverEngine:
    def __init__(self, nameserver: str = None, timeout: float = 5.0, retries: int = 3, use_tcp: bool = False):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.retries = retries
        self.use_tcp = use_tcp
        if nameserver:
            self.resolver.nameservers = [nameserver]

    def query_record(self, domain: str, record_type: str) -> dict:
        """
        Performs a robust DNS query returning structured records with priority and TTL.
        """
        r_type = record_type.upper()
        target_domain = encode_idn(domain)

        attempt = 0
        while attempt < self.retries:
            try:
                answers = self.resolver.resolve(target_domain, r_type, tcp=self.use_tcp)
                records = []

                for rdata in answers:
                    priority = None
                    value = str(rdata)

                    if r_type == "TXT" and hasattr(rdata, "strings"):
                        value = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    elif r_type == "MX" and hasattr(rdata, "preference"):
                        priority = rdata.preference
                        value = str(rdata.exchange).rstrip(".")
                    elif r_type == "SRV" and hasattr(rdata, "priority"):
                        priority = rdata.priority
                        value = f"{rdata.weight} {rdata.port} {str(rdata.target).rstrip('.')}"
                    elif r_type in ("NS", "CNAME"):
                        value = value.rstrip(".")

                    records.append({
                        "value": value,
                        "priority": priority
                    })

                return {
                    "status": "SUCCESS",
                    "domain": domain,
                    "punycode": target_domain if target_domain != domain else None,
                    "type": r_type,
                    "records": records,
                    "ttl": answers.rrset.ttl
                }
            except dns.resolver.NXDOMAIN:
                return {
                    "status": "ERROR",
                    "type": r_type,
                    "message": f"Domain '{domain}' does not exist (NXDOMAIN)."
                }
            except dns.resolver.NoAnswer:
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

                sleep_time = 2 ** (attempt - 1)
                time.sleep(sleep_time)
