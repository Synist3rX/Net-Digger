from unittest.mock import patch

import pytest

from core.whois_inspector import inspect_whois


def _fake_raw_query_side_effect(responses: dict[tuple[str, str], str]):
    """Devuelve respuestas simuladas según (server, query)."""

    def _side_effect(server: str, query: str, timeout: float = 5.0) -> str:
        key = (server.lower(), query.lower())
        if key in responses:
            return responses[key]
        raise AssertionError(f"Unexpected WHOIS query: server={server!r}, query={query!r}")

    return _side_effect


def test_whois_full_flow_dates_nameservers_and_epp_statuses():
    """Verifica extracción de campos, fechas, antigüedad/plazo, NS y códigos EPP."""
    raw_whois = """
Domain Name: GOOGLE.COM
Registrar: MarkMonitor Inc.
Registrar URL: http://www.markmonitor.com
Registrant Country: US
DNSSEC: unsigned
Creation Date: 1997-09-15T04:00:00Z
Updated Date: 2019-09-09T15:39:04Z
Registry Expiry Date: 2028-09-14T04:00:00Z
Name Server: ns1.google.com
Name Server: NS1.GOOGLE.COM
Name Server: ns2.google.com
Name Server: ns3.google.com
Name Server: ns4.google.com
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
"""

    responses = {
        ("whois.iana.org", "com"): "refer: whois.verisign-grs.com\n",
        ("whois.verisign-grs.com", "google.com"): raw_whois,
    }

    with patch("core.whois_inspector._raw_whois_query", side_effect=_fake_raw_query_side_effect(responses)):
        result = inspect_whois("google.com", timeout=3.0)

    assert result["status"] == "SUCCESS"
    assert result["domain"] == "GOOGLE.COM"
    assert result["registrar"] == "MarkMonitor Inc."
    assert result["registrar_url"] == "http://www.markmonitor.com"
    assert result["country"] == "US"
    assert result["dnssec"] == "unsigned"
    assert result["registered"] == "Sep 15, 1997"
    assert result["updated"] == "Sep 9, 2019"
    assert result["expires"] == "Sep 14, 2028"
    assert result["term_years"] == 31
    assert isinstance(result["years_ago"], int)
    assert result["years_ago"] >= 28

    # Nameservers en mayúsculas y sin duplicados
    assert result["nameservers"] == [
        "NS1.GOOGLE.COM",
        "NS2.GOOGLE.COM",
        "NS3.GOOGLE.COM",
        "NS4.GOOGLE.COM",
    ]

    # Estados EPP limpios sin URLs ni duplicados
    assert result["statuses"] == [
        "clientDeleteProhibited",
        "clientTransferProhibited",
        "clientUpdateProhibited",
        "serverDeleteProhibited",
        "serverTransferProhibited",
        "serverUpdateProhibited",
    ]


def test_whois_follows_registrar_referral_and_merges_data():
    """Verifica el salto de IANA -> TLD WHOIS -> Registrar WHOIS y combinación de campos."""
    tld_response = """
Domain Name: EXAMPLE.COM
Registrar WHOIS Server: whois.example-registrar.net
Registrar: Example Registrar Ltd.
Name Server: NS1.EXAMPLE.COM
"""
    registrar_response = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar Ltd.
Registrar URL: https://example-registrar.net
Registrant Country: ES
DNSSEC: signedDelegation
Creation Date: 2020-05-01T10:00:00Z
Updated Date: 2024-01-15T08:30:00Z
Registry Expiry Date: 2027-05-01T10:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
Domain Status: clientTransferProhibited
"""

    responses = {
        ("whois.iana.org", "com"): "refer: whois.verisign-grs.com\n",
        ("whois.verisign-grs.com", "example.com"): tld_response,
        ("whois.example-registrar.net", "example.com"): registrar_response,
    }

    with patch("core.whois_inspector._raw_whois_query", side_effect=_fake_raw_query_side_effect(responses)) as mock_q:
        result = inspect_whois("example.com")

        assert mock_q.call_count == 3
        assert result["status"] == "SUCCESS"
        assert result["country"] == "ES"
        assert result["dnssec"] == "signed"
        assert result["registered"] == "May 1, 2020"
        assert result["expires"] == "May 1, 2027"
        assert result["term_years"] == 7
        assert result["nameservers"] == ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]
        assert result["statuses"] == ["clientTransferProhibited"]


def test_whois_handles_multiple_date_formats():
    """Verifica el parseo de formatos de fecha alternativos sin zona explícita o con slash/punto."""
    raw_whois = """
Domain Name: TEST-DATES.ORG
Registrar: ORG Registry Test
Creation Date: 2015-06-05 12:00:00
Updated Date: 2022/03/09
Registry Expiry Date: 2030-06-05
Name Server: ns1.test-dates.org
Domain Status: ok
"""

    responses = {
        ("whois.iana.org", "org"): "refer: whois.pir.org\n",
        ("whois.pir.org", "test-dates.org"): raw_whois,
    }

    with patch("core.whois_inspector._raw_whois_query", side_effect=_fake_raw_query_side_effect(responses)):
        result = inspect_whois("test-dates.org")

    assert result["status"] == "SUCCESS"
    assert result["registered"] == "Jun 5, 2015"
    assert result["updated"] == "Mar 9, 2022"
    assert result["expires"] == "Jun 5, 2030"
    assert result["term_years"] == 15
    assert result["statuses"] == ["ok"]


def test_whois_connection_error_returns_structured_error():
    """Verifica que un fallo de red o timeout en puerto 43 devuelva status='ERROR'."""
    with patch("core.whois_inspector._raw_whois_query", side_effect=OSError("Connection timed out")):
        result = inspect_whois("timeout-domain.com", timeout=2.0)

    assert result["status"] == "ERROR"
    assert result["domain"] == "TIMEOUT-DOMAIN.COM"
    assert "WHOIS lookup failed" in result["message"]


def test_whois_empty_response_returns_error():
    """Verifica que una respuesta WHOIS vacía devuelva status='ERROR'."""
    responses = {
        ("whois.iana.org", "com"): "refer: whois.verisign-grs.com\n",
        ("whois.verisign-grs.com", "empty-domain.com"): "   \r\n  ",
    }

    with patch("core.whois_inspector._raw_whois_query", side_effect=_fake_raw_query_side_effect(responses)):
        result = inspect_whois("empty-domain.com")

    assert result["status"] == "ERROR"
    assert result["domain"] == "EMPTY-DOMAIN.COM"
    assert "Empty WHOIS response" in result["message"]
