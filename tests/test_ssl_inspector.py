import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from core.ssl_inspector import inspect_ssl_certificate


def _format_openssl_date(dt: datetime) -> str:
    """Genera fechas en el formato típico de X.509/OpenSSL (ej. 'Nov 3 00:00:00 2026 GMT')."""
    return dt.astimezone(timezone.utc).strftime("%b %d %H:%M:%S %Y GMT")


def _build_mock_ssl_env(cert_dict: dict, protocol: str = "TLSv1.3", cipher_name: str = "TLS_AES_256_GCM_SHA384"):
    """Crea un contexto y socket SSL simulados que devuelven el certificado indicado."""
    mock_ssock = MagicMock()
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = None
    mock_ssock.getpeercert.return_value = cert_dict
    mock_ssock.version.return_value = protocol
    mock_ssock.cipher.return_value = (cipher_name, "TLSv1.3", 256)

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.__exit__.return_value = None

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_ssock

    return mock_sock, mock_ctx


def test_inspect_valid_certificate_and_sans():
    """Verifica certificado vigente, coincidencia por wildcard en SANs y metadatos."""
    now = datetime.now(timezone.utc)
    valid_from = now - timedelta(days=20)
    expires = now + timedelta(days=61)

    cert = {
        "subject": ((("commonName", "*.google.com"),),),
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "Google Trust Services"),),
        ),
        "notBefore": _format_openssl_date(valid_from),
        "notAfter": _format_openssl_date(expires),
        "subjectAltName": (
            ("DNS", "*.google.com"),
            ("DNS", "google.com"),
            ("DNS", "*.cloud.google.com"),
            ("DNS", "mail.google.com"),
        ),
    }

    mock_sock, mock_ctx = _build_mock_ssl_env(cert)

    with patch("socket.create_connection", return_value=mock_sock) as mock_conn, \
         patch("ssl.create_default_context", return_value=mock_ctx):
        result = inspect_ssl_certificate("google.com", port=443, timeout=3.0)

        mock_conn.assert_called_once_with(("google.com", 443), timeout=3.0)
        assert mock_ctx.verify_mode == ssl.CERT_OPTIONAL
        assert mock_ctx.check_hostname is False
        mock_ctx.wrap_socket.assert_called_once_with(mock_sock, server_hostname="google.com")

        assert result["status"] == "SUCCESS"
        assert result["common_name"] == "*.google.com"
        assert result["issuer"] == "Google Trust Services"
        assert result["days_remaining"] in (60, 61)
        assert result["expired"] is False
        assert result["domain_included"] is True
        assert result["is_self_signed"] is False
        assert result["sans_count"] == 4
        assert "*.cloud.google.com" in result["sans"]
        assert result["tls_version"] == "TLSv1.3"


def test_inspect_expired_certificate():
    """Verifica que un certificado vencido reporte expired=True y días restantes negativos."""
    now = datetime.now(timezone.utc)
    valid_from = now - timedelta(days=90)
    expires = now - timedelta(days=10)

    cert = {
        "subject": ((("commonName", "expired.example.org"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "notBefore": _format_openssl_date(valid_from),
        "notAfter": _format_openssl_date(expires),
        "subjectAltName": (("DNS", "expired.example.org"),),
    }

    mock_sock, mock_ctx = _build_mock_ssl_env(cert)

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", return_value=mock_ctx):
        result = inspect_ssl_certificate("expired.example.org")

        assert result["status"] == "SUCCESS"
        assert result["expired"] is True
        assert result["days_remaining"] is not None
        assert result["days_remaining"] < 0
        assert result["domain_included"] is True


def test_inspect_self_signed_certificate():
    """Verifica que cuando subject == issuer se marque is_self_signed=True."""
    now = datetime.now(timezone.utc)
    valid_from = now - timedelta(days=1)
    expires = now + timedelta(days=365)

    same_dn = ((("commonName", "internal.local"),), (("organizationName", "Internal Lab"),),)
    cert = {
        "subject": same_dn,
        "issuer": same_dn,
        "notBefore": _format_openssl_date(valid_from),
        "notAfter": _format_openssl_date(expires),
        "subjectAltName": (("DNS", "internal.local"),),
    }

    mock_sock, mock_ctx = _build_mock_ssl_env(cert)

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", return_value=mock_ctx):
        result = inspect_ssl_certificate("internal.local")

        assert result["status"] == "SUCCESS"
        assert result["is_self_signed"] is True
        assert result["issuer"] == "Internal Lab"
        assert result["domain_included"] is True


def test_inspect_domain_not_in_sans_or_cn():
    """Verifica que domain_included sea False si el dominio no figura en CN ni en SANs."""
    now = datetime.now(timezone.utc)
    cert = {
        "subject": ((("commonName", "other-site.com"),),),
        "issuer": ((("organizationName", "DigiCert Inc"),),),
        "notBefore": _format_openssl_date(now - timedelta(days=5)),
        "notAfter": _format_openssl_date(now + timedelta(days=30)),
        "subjectAltName": (("DNS", "other-site.com"), ("DNS", "www.other-site.com")),
    }

    mock_sock, mock_ctx = _build_mock_ssl_env(cert)

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", return_value=mock_ctx):
        result = inspect_ssl_certificate("target-domain.com")

        assert result["status"] == "SUCCESS"
        assert result["domain_included"] is False
        assert result["sans_count"] == 2


def test_inspect_connection_timeout_returns_error():
    """Verifica que un fallo de red o timeout devuelva status='ERROR' sin romper la ejecución."""
    with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
        result = inspect_ssl_certificate("unreachable.example.com", port=443, timeout=1.0)

        assert result["status"] == "ERROR"
        assert result["domain"] == "unreachable.example.com"
        assert result["port"] == 443
        assert "SSL/TLS inspection failed" in result["message"]


def test_inspect_empty_certificate_returns_error():
    """Verifica que si getpeercert() devuelve vacío se reporte status='ERROR'."""
    mock_sock, mock_ctx = _build_mock_ssl_env({})

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", return_value=mock_ctx):
        result = inspect_ssl_certificate("no-cert.example.com")

        assert result["status"] == "ERROR"
        assert "did not return a structured certificate" in result["message"]
