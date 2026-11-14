import pytest
from unittest.mock import MagicMock, patch
from core.resolver import DNSResolverEngine

@pytest.fixture
def resolver_engine():
    return DNSResolverEngine(nameserver="1.1.1.1", timeout=2.0)

def test_query_record_success(resolver_engine):
    # Mock de la respuesta de dnspython
    mock_rdata = MagicMock()
    mock_rdata.__str__.return_value = "93.184.215.14"
    
    mock_answer = MagicMock()
    mock_answer.__iter__.return_value = [mock_rdata]
    mock_answer.rrset.ttl = 300

    with patch.object(resolver_engine.resolver, "resolve", return_value=mock_answer) as mock_resolve:
        result = resolver_engine.query_record("example.com", "A")
        
        mock_resolve.assert_called_once_with("example.com", "A")
        assert result["status"] == "SUCCESS"
        assert result["domain"] == "example.com"
        assert result["type"] == "A"
        assert result["data"] == ["93.184.215.14"]
        assert result["ttl"] == 300

def test_query_record_nxdomain(resolver_engine):
    import dns.resolver
    with patch.object(resolver_engine.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
        result = resolver_engine.query_record("invalid-domain-xyz.com", "A")
        
        assert result["status"] == "ERROR"
        assert result["type"] == "A"
        assert "does not exist (NXDOMAIN)" in result["message"]

def test_query_record_timeout(resolver_engine):
    import dns.exception
    with patch.object(resolver_engine.resolver, "resolve", side_effect=dns.exception.Timeout):
        result = resolver_engine.query_record("example.com", "A")
        
        assert result["status"] == "ERROR"
        assert result["type"] == "A"
        assert "timed out" in result["message"]
