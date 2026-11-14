import dns.resolver
import dns.exception
from core.validator import encode_idn

class DNSResolverEngine:
    def __init__(self, nameserver: str = None, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if nameserver:
            self.resolver.nameservers = [nameserver]

    def query_record(self, domain: str, record_type: str) -> dict:
        """
        Performs a robust DNS query for a specific record type supporting IDN domains.
        """
        r_type = record_type.upper()
        # Convert IDN unicode domain to Punycode if necessary
        target_domain = encode_idn(domain)
        
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
        except dns.exception.Timeout:
            return {
                "status": "ERROR",
                "type": r_type,
                "message": "DNS query timed out."
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "type": r_type,
                "message": str(e)
            }
