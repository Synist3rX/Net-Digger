import re
import ipaddress

def is_valid_domain(domain: str) -> bool:
    """
    Validates domain format (supporting IDN via punycode conversion).
    """
    if not domain or len(domain) > 253:
        return False
    
    try:
        ascii_domain = domain.encode('idna').decode('ascii')
    except UnicodeError:
        return False

    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(ascii_domain))

def encode_idn(domain: str) -> str:
    """
    Encodes an Internationalized Domain Name (IDN) to Punycode.
    """
    try:
        return domain.encode('idna').decode('ascii')
    except UnicodeError:
        return domain

def is_valid_ip(ip: str) -> bool:
    """
    Validates if a string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
