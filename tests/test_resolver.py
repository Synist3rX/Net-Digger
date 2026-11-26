import pytest
import dns.resolver
import dns.exception
from unittest.mock import MagicMock, patch
from core.resolver import DNSResolverEngine


@pytest.fixture
def resolver_engine():
    return DNSResolverEngine(nameserver="1.1.1.1", timeout=2.0, retries=3)


def test_query_record_success(resolver_engine):
    """Prueba una consulta DNS exitosa en el primer intento."""
    mock_rdata = MagicMock()
    mock_rdata.__str__.return_value = "93.184.215.14"

    mock_answer = MagicMock()
    mock_answer.__iter__.return_value = [mock_rdata]
    mock_answer.rrset.ttl = 300

    with patch.object(resolver_engine.resolver, "resolve", return_value=mock_answer) as mock_resolve:
        result = resolver_engine.query_record("example.com", "A")

        mock_resolve.assert_called_once_with("example.com", "A", tcp=False)
        assert result["status"] == "SUCCESS"
        assert result["domain"] == "example.com"
        assert result["type"] == "A"
        assert result["records"] == [{"value": "93.184.215.14", "priority": None}]
        assert result["ttl"] == 300


def test_query_record_nxdomain(resolver_engine):
    """Prueba que errores definitivos como NXDOMAIN no disparen reintentos innecesarios."""
    with patch.object(resolver_engine.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN) as mock_resolve:
        result = resolver_engine.query_record("invalid-domain-xyz.com", "A")

        mock_resolve.assert_called_once()
        assert result["status"] == "ERROR"
        assert result["type"] == "A"
        assert "does not exist (NXDOMAIN)" in result["message"]


def test_query_record_no_answer(resolver_engine):
    """Prueba que el error NoAnswer devuelva un estado de error estructurado."""
    with patch.object(resolver_engine.resolver, "resolve", side_effect=dns.resolver.NoAnswer) as mock_resolve:
        result = resolver_engine.query_record("example.com", "MX")

        mock_resolve.assert_called_once()
        assert result["status"] == "ERROR"
        assert result["type"] == "MX"
        assert "No MX records found" in result["message"]


def test_query_retry_success_on_second_attempt(resolver_engine):
    """Prueba que un fallo temporal (Timeout) active el reintento y tenga éxito en el segundo intento."""
    mock_rdata = MagicMock()
    mock_rdata.__str__.return_value = "93.184.215.14"

    mock_answer = MagicMock()
    mock_answer.__iter__.return_value = [mock_rdata]
    mock_answer.rrset.ttl = 300

    with patch.object(
        resolver_engine.resolver, "resolve", side_effect=[dns.exception.Timeout, mock_answer]
    ) as mock_resolve, patch("time.sleep", return_value=None) as mock_sleep:

        result = resolver_engine.query_record("example.com", "A")

        assert mock_resolve.call_count == 2
        assert mock_sleep.call_count == 1
        assert result["status"] == "SUCCESS"
        assert result["records"] == [{"value": "93.184.215.14", "priority": None}]


def test_query_retry_exhausted(resolver_engine):
    """Prueba que al agotarse todos los reintentos se devuelva un error estructurado y el backoff respectivo."""
    with patch.object(resolver_engine.resolver, "resolve", side_effect=dns.exception.Timeout) as mock_resolve, \
         patch("time.sleep", return_value=None) as mock_sleep:

        result = resolver_engine.query_record("example.com", "A")

        assert mock_resolve.call_count == 3
        assert mock_sleep.call_count == 2
        assert result["status"] == "ERROR"
        assert result["type"] == "A"
        assert "DNS query failed after 3 attempts" in result["message"]


def test_query_record_idn_support(resolver_engine):
    """Prueba que los dominios con caracteres IDN incluyan la clave punycode en el resultado exitoso."""
    mock_rdata = MagicMock()
    mock_rdata.__str__.return_value = "185.199.108.153"

    mock_answer = MagicMock()
    mock_answer.__iter__.return_value = [mock_rdata]
    mock_answer.rrset.ttl = 3600

    with patch.object(resolver_engine.resolver, "resolve", return_value=mock_answer) as mock_resolve:
        result = resolver_engine.query_record("eñe.es", "A")

        mock_resolve.assert_called_once_with("xn--ee-zja.es", "A", tcp=False)
        assert result["status"] == "SUCCESS"
        assert result["domain"] == "eñe.es"
        assert result["punycode"] == "xn--ee-zja.es"
        assert result["records"] == [{"value": "185.199.108.153", "priority": None}]


def test_query_record_txt_strips_quotes(resolver_engine):
    """Prueba que los registros TXT se extraigan limpiamente sin comillas envolventes."""
    mock_rdata = MagicMock()
    mock_rdata.strings = (b"v=spf1 include:_spf.google.com ~all",)

    mock_answer = MagicMock()
    mock_answer.__iter__.return_value = [mock_rdata]
    mock_answer.rrset.ttl = 3600

    with patch.object(resolver_engine.resolver, "resolve", return_value=mock_answer):
        result = resolver_engine.query_record("example.com", "TXT")

        assert result["status"] == "SUCCESS"
        assert result["records"] == [
            {"value": "v=spf1 include:_spf.google.com ~all", "priority": None}
        ]
