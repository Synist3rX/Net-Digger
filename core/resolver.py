import dns.resolver
import dns.exception

class DNSResolverEngine:
    def __init__(self, nameserver: str = None, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if nameserver:
            self.resolver.nameservers = [nameserver]

    def query_record(self, domain: str, record_type: str) -> dict:
        """
        Performs a robust DNS query for a specific record type.
        """
        r_type = record_type.upper()
        try:
            answers = self.resolver.resolve(domain, r_type)
            results = [str(rdata) for rdata in answers]
            return {
                "status": "SUCCESS",
                "domain": domain,
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
