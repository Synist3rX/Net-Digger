def detect_dns_provider(ns_records: list[str]) -> str:
    """Infers the DNS Provider based on NS record hostnames."""
    if not ns_records:
        return "Unknown"

    joined = " ".join(ns_records).lower()
    signatures = {
        "Cloudflare": ["cloudflare.com"],
        "Google Cloud DNS": ["googledomains.com", "google.com", "ns-cloud-"],
        "AWS Route 53": ["awsdns-"],
        "Azure DNS": ["azure-dns."],
        "GoDaddy": ["domaincontrol.com"],
        "Namecheap": ["registrar-servers.com"],
        "DigitalOcean": ["digitalocean.com"],
        "Vercel": ["vercel-dns.com"],
        "Netlify": ["nsone.net"]
    }

    for provider, patterns in signatures.items():
        if any(pattern in joined for pattern in patterns):
            return provider
    return "Custom / Other"

def detect_email_provider(mx_records: list[str]) -> str:
    """Infers the Email Provider based on MX record exchange hostnames."""
    if not mx_records:
        return "None / Not configured"

    joined = " ".join(mx_records).lower()
    signatures = {
        "Google Workspace": ["google.com", "googlemail.com"],
        "Microsoft 365": ["outlook.com", "protection.outlook.com"],
        "Zoho Mail": ["zoho.com", "zoho.eu"],
        "Proton Mail": ["protonmail.ch"],
        "Mimecast": ["mimecast.com"],
        "Proofpoint": ["pphosted.com"],
        "Fastmail": ["messagingengine.com"],
        "Amazon SES": ["amazonses.com"],
        "Cloudflare Email Routing": ["mx.cloudflare.net"]
    }

    for provider, patterns in signatures.items():
        if any(pattern in joined for pattern in patterns):
            return provider
    return "Custom / Self-Hosted"
