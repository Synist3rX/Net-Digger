import pytest
from core.validator import is_valid_domain, encode_idn, is_valid_ip

@pytest.mark.parametrize("domain,expected", [
    ("example.com", True),
    ("sub.example.co.uk", True),
    ("eñe.es", True),
    ("münchen.de", True),
    ("invalid_domain", False),
    ("-invalid.com", False),
    ("example..com", False),
    ("", False),
])
def test_is_valid_domain(domain, expected):
    """Prueba la validación estricta de dominios, incluyendo formato IDN."""
    assert is_valid_domain(domain) == expected

@pytest.mark.parametrize("domain,expected_punycode", [
    ("example.com", "example.com"),
    ("eñe.es", "xn--ee-zja.es"),
    ("münchen.de", "xn--mnchen-3ya.de"),
])
def test_encode_idn(domain, expected_punycode):
    """Prueba la conversión correcta de caracteres internacionales a Punycode."""
    assert encode_idn(domain) == expected_punycode

@pytest.mark.parametrize("ip,expected", [
    ("1.1.1.1", True),
    ("8.8.8.8", True),
    ("2606:4700:4700::1111", True),
    ("256.0.0.1", False),
    ("abc.def.ghi.jkl", False),
    ("192.168.1", False),
    ("", False),
])
def test_is_valid_ip(ip, expected):
    """Prueba la validación de direcciones IP (IPv4 e IPv6) para custom nameservers."""
    assert is_valid_ip(ip) == expected
