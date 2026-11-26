from unittest.mock import MagicMock, patch

import pytest

from core.formatters import INTERN_SEPARATOR_WIDTH, SEPARATOR_WIDTH, format_dns_records_block
from digger import load_domains_from_file, parse_record_types, process_single_domain


def test_parse_record_types_modes():
    """Cubre sin -t (solo target), -t sin valor (ALL), tipos personalizados y --all."""
    show_none, types_none = parse_record_types(None, include_all_flag=False)
    assert (show_none, types_none) == (False, [])

    show_t, types_t = parse_record_types("ALL", include_all_flag=False)
    assert show_t is True
    assert {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR", "HTTPS", "SVCB"}.issubset(
        set(types_t)
    )

    show_custom, types_custom = parse_record_types("mx, a, MX", include_all_flag=False)
    assert (show_custom, types_custom) == (True, ["MX", "A"])

    show_all, types_all = parse_record_types(None, include_all_flag=True)
    assert show_all is True
    assert len(types_all) == 12


@pytest.mark.parametrize("bad_type", ["INVALID", "A,FOO", "   "])
def test_parse_record_types_rejects_invalid(bad_type):
    with pytest.raises(ValueError):
        parse_record_types(bad_type, include_all_flag=False)


def test_process_single_domain_visibility_and_dns_count():
    """Verifica que sin -t solo se muestre Target y con -t aparezca DNS Records con su contador."""
    engine = MagicMock()
    engine.resolver.timeout = 3.0
    engine.query_record.return_value = {
        "status": "SUCCESS",
        "type": "A",
        "ttl": 300,
        "records": [{"value": "93.184.216.34", "priority": None}],
    }
    fake_target = {
        "query": "example.com",
        "ip": "93.184.216.34",
        "ptr": "edge.example.com",
        "resolves_to": "93.184.216.34 (edge.example.com)",
        "http_status": 200,
    }

    with (
        patch("digger.gather_target_metadata", return_value=fake_target),
        patch("digger.tqdm.write") as mock_write,
    ):
        process_single_domain("example.com", engine, [], show_dns_records=False)
        only_target = mock_write.call_args[0][0]
        assert "[>] Target: example.com" in only_target
        assert "Resolves To     : 93.184.216.34 (edge.example.com)" in only_target
        assert "HTTP Status     : 200" in only_target
        assert "[>] DNS Records" not in only_target
        assert "records found" not in only_target

        process_single_domain("example.com", engine, ["A"], show_dns_records=True)
        with_dns = mock_write.call_args[0][0]
        assert "[>] Target: example.com" in with_dns
        assert "records found" not in with_dns.splitlines()[1]
        assert "[>] DNS Records (1 records found)" in with_dns
        assert "93.184.216.34" in with_dns


def test_format_dns_records_block_separators_and_providers():
    """Comprueba separadores constantes, truncado y detección de proveedores NS/MX."""
    rows = [("A", "1.2.3.4", "", "120s"), ("NS", "ns1.example.com", "", "600s")]
    lines = format_dns_records_block(
        table_rows=rows,
        total_records=2,
        record_types=["A", "NS"],
        dns_provider="Cloudflare",
        full_output=False,
    )
    rendered = "\n".join(lines)
    assert ("-" * SEPARATOR_WIDTH) in rendered
    assert ("    " + "-" * INTERN_SEPARATOR_WIDTH) in rendered
    assert "[>] DNS Records (2 records found)" in rendered
    assert "DNS Provider   : Cloudflare (detected via NS)" in rendered


def test_load_domains_from_file_skips_comments_and_invalid(tmp_path):
    """Carga dominios válidos ignorando comentarios, líneas vacías y formatos inválidos."""
    domain_file = tmp_path / "domains.txt"
    domain_file.write_text("# comentario\n\nexample.com\ninvalid_domain\neñe.es\n", encoding="utf-8")

    with patch("digger.tqdm.write") as mock_warn:
        loaded = load_domains_from_file(str(domain_file))

    assert loaded == ["example.com", "eñe.es"]
    mock_warn.assert_called_once()


def test_main_rejects_both_positional_and_flag_domain(monkeypatch, capsys):
    """Rechaza pasar dominio posicional y -d al mismo tiempo."""
    from digger import main

    monkeypatch.setattr("sys.argv", ["digger.py", "google.com", "-d", "example.com"])
    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1
    assert "not both" in capsys.readouterr().out.lower()


def test_main_rejects_missing_target(monkeypatch, capsys):
    """Sale con código 1 cuando no se indica dominio posicional, -d ni -f."""
    from digger import main

    monkeypatch.setattr("sys.argv", ["digger.py"])
    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1
    assert "must specify" in capsys.readouterr().out.lower()

def test_process_single_domain_runs_blacklist_module():
    engine = MagicMock()
    engine.resolver.timeout = 3.0

    fake_target = {
        "query": "example.com",
        "ip": "142.251.215.238",
        "ptr": None,
        "resolves_to": "142.251.215.238",
        "http_status": 200,
    }
    fake_blacklist = {
        "status": "SUCCESS",
        "overall_status": "Clean",
        "checked_ip": "142.251.215.238",
        "total_checked": 13,
        "clean_count": 13,
        "listed_count": 0,
        "error_count": 0,
        "checks": [],
    }

    with (
        patch("digger.gather_target_metadata", return_value=fake_target),
        patch("digger.inspect_blacklist_block", return_value=fake_blacklist) as mock_bl,
        patch("digger.tqdm.write") as mock_write,
    ):
        res = process_single_domain(
            domain="example.com",
            engine=engine,
            record_types=[],
            show_dns_records=False,
            inspect_blacklist=True,
            full_output=False,
        )

    mock_bl.assert_called_once_with(domain="example.com", engine=engine, ip="142.251.215.238")
    rendered = mock_write.call_args[0][0]
    assert "[>] Blacklist Check" in rendered
    assert "Overall         : Clean" in rendered
    assert "Clean: 13/13" in rendered
    assert res["blacklist"] == fake_blacklist

def test_process_single_domain_runs_blacklist_and_headers():
    engine = MagicMock()
    engine.resolver.timeout = 5.0

    fake_target = {
        "query": "google.com",
        "ip": "142.251.45.14",
        "ptr": None,
        "resolves_to": "142.251.45.14",
        "http_status": 200,
    }
    fake_blacklist = {
        "status": "SUCCESS",
        "overall_status": "Listed",
        "checked_ip": "142.251.45.14",
        "checked_domain": "google.com",
        "total_checked": 13,
        "listed_count": 2,
        "clean_count": 11,
        "error_count": 0,
        "checks": [
            {"name": "Spamhaus PBL", "scope": "ip", "status": "Listed", "response": "Listed", "message": None},
            {"name": "URIBL", "scope": "domain", "status": "Listed", "response": "Listed", "message": None},
        ],
    }
    fake_headers = {
        "status": "SUCCESS",
        "final_url": "http://www.google.com/",
        "status_code": 200,
        "redirect_chain": [
            {"status_code": 301, "url": "http://google.com", "location": "http://www.google.com/"},
            {"status_code": 200, "url": "http://www.google.com/", "location": None},
        ],
        "security_headers": {"present_count": 2, "total_count": 7, "items": []},
        "all_headers": {"server": "gws"},
    }

    with (
        patch("digger.gather_target_metadata", return_value=fake_target),
        patch("digger.inspect_blacklist_block", return_value=fake_blacklist) as mock_bl,
        patch("digger.inspect_http_headers", return_value=fake_headers) as mock_hdr,
        patch("digger.tqdm.write") as mock_write,
    ):
        res = process_single_domain(
            domain="google.com",
            engine=engine,
            record_types=[],
            show_dns_records=False,
            inspect_blacklist=True,
            inspect_headers=True,
            full_output=False,
        )

    mock_bl.assert_called_once_with(domain="google.com", engine=engine, ip="142.251.45.14")
    mock_hdr.assert_called_once_with(target="google.com", engine=engine)

    rendered = mock_write.call_args[0][0]
    assert "[>] Blacklist Check" in rendered
    assert "[>] HTTP & Headers" in rendered
    assert res["blacklist"] == fake_blacklist
    assert res["http_headers"] == fake_headers
