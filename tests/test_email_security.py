from unittest.mock import MagicMock

import pytest

from core.email_security import inspect_email_security


def _make_mock_engine(txt_map: dict[str, list[str]]):
    """Crea un mock de DNSResolverEngine que responde registros TXT según el qname."""
    engine = MagicMock()

    def _query_record(qname: str, r_type: str):
        assert r_type == "TXT"
        key = qname.lower().rstrip(".")
        values = txt_map.get(key)
        if not values:
            return {"status": "NXDOMAIN", "type": "TXT", "records": []}
        return {
            "status": "SUCCESS",
            "type": "TXT",
            "ttl": 300,
            "records": [{"value": v, "priority": None} for v in values],
        }

    engine.query_record.side_effect = _query_record
    return engine


def test_spf_softfail_lookups_dmarc_and_dkim_detected():
    """Verifica SPF (~all), conteo de lookups con include anidado, DMARC y selectores DKIM."""
    txt_map = {
        "example.com": [
            "v=spf1 include:_spf.provider.com mx ~all",
        ],
        "_spf.provider.com": [
            "v=spf1 include:spf.sub.provider.com ip4:198.51.100.10 ~all",
        ],
        "spf.sub.provider.com": [
            "v=spf1 ip4:198.51.100.20 -all",
        ],
        "_dmarc.example.com": [
            "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
        ],
        "google._domainkey.example.com": [
            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
        ],
    }

    engine = _make_mock_engine(txt_map)
    result = inspect_email_security(
        "example.com",
        engine,
        dkim_selectors=("default", "google", "selector1"),
    )

    assert result["status"] == "SUCCESS"
    assert result["domain"] == "example.com"

    # SPF: 1 (include:_spf.provider.com) + 1 (include:spf.sub.provider.com) + 1 (mx) = 3 lookups
    assert result["spf"]["found"] is True
    assert result["spf"]["status"] == "Soft Fail (~all)"
    assert result["spf"]["lookups"] == 3
    assert result["spf"]["max_lookups"] == 10
    assert result["spf"]["record"] == "v=spf1 include:_spf.provider.com mx ~all"

    # DMARC
    assert result["dmarc"]["found"] is True
    assert result["dmarc"]["policy"] == "quarantine"
    assert result["dmarc"]["reports"] == "mailto:dmarc@example.com"
    assert result["dmarc"]["record"].startswith("v=DMARC1;")

    # DKIM
    assert result["dkim"]["found"] is True
    assert result["dkim"]["status"] == "Detected"
    assert result["dkim"]["selectors"] == ["google"]

    # Con ~all (no -all) resulta en Partial
    assert result["overall_status"] == "Partial"


def test_spf_strong_posture_with_reject_and_dkim():
    """Verifica postura Strong cuando hay SPF -all, DMARC reject y al menos un selector DKIM."""
    txt_map = {
        "secure.org": ["v=spf1 ip4:203.0.113.5 -all"],
        "_dmarc.secure.org": ["v=DMARC1; p=reject; rua=mailto:postmaster@secure.org"],
        "s1._domainkey.secure.org": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA"],
    }

    engine = _make_mock_engine(txt_map)
    result = inspect_email_security("secure.org", engine, dkim_selectors=("s1", "s2"))

    assert result["spf"]["status"] == "Fail (-all)"
    assert result["spf"]["lookups"] == 0
    assert result["dmarc"]["policy"] == "reject"
    assert result["dkim"]["found"] is True
    assert result["overall_status"] == "Strong"


def test_spf_lookup_cycle_protection():
    """Verifica que un ciclo en include:/redirect= no provoque recursión infinita."""
    txt_map = {
        "loop.test": ["v=spf1 include:a.loop.test -all"],
        "a.loop.test": ["v=spf1 include:loop.test ~all"],
    }

    engine = _make_mock_engine(txt_map)
    result = inspect_email_security("loop.test", engine, dkim_selectors=())

    assert result["status"] == "SUCCESS"
    assert result["spf"]["found"] is True
    # loop.test -> include:a.loop.test (+1) -> include:loop.test (+1); al volver a loop.test ya está visitado
    assert result["spf"]["lookups"] == 2


def test_missing_email_security_records():
    """Verifica comportamiento cuando no existen SPF, DMARC ni selectores DKIM."""
    engine = _make_mock_engine({})
    result = inspect_email_security("plain.dev", engine, dkim_selectors=("default", "google"))

    assert result["status"] == "SUCCESS"
    assert result["overall_status"] == "Missing"
    assert result["spf"]["found"] is False
    assert result["spf"]["status"] == "Missing"
    assert result["spf"]["lookups"] == 0
    assert result["dmarc"]["found"] is False
    assert result["dmarc"]["policy"] is None
    assert result["dkim"]["found"] is False
    assert result["dkim"]["status"] == "Not detected"
    assert result["dkim"]["detail"] == "No selectors found from common list"
