from unittest.mock import MagicMock, patch

import pytest

from digger import parse_record_types, process_single_domain


def test_parse_record_types_modes():
    # Sin -t ni --all -> solo target
    show, types = parse_record_types(None, include_all_flag=False)
    assert show is False
    assert types == []

    # -t sin valor (const="ALL") -> muestra DNS records con ALL
    show_t, types_t = parse_record_types("ALL", include_all_flag=False)
    assert show_t is True
    assert "A" in types_t and "MX" in types_t and "SVCB" in types_t

    # -t con tipos específicos y duplicados
    show_custom, types_custom = parse_record_types("mx, a, MX", include_all_flag=False)
    assert show_custom is True
    assert types_custom == ["MX", "A"]

    # --all sin -t explícito -> activa DNS records con ALL
    show_all, types_all = parse_record_types(None, include_all_flag=True)
    assert show_all is True
    assert len(types_all) > 5


@pytest.mark.parametrize("bad_type", ["INVALID", "A,FOO", "   "])
def test_parse_record_types_rejects_invalid(bad_type):
    with pytest.raises(ValueError):
        parse_record_types(bad_type, include_all_flag=False)


def test_process_single_domain_hides_dns_table_without_t():
    engine = MagicMock()
    engine.resolver.timeout = 3.0

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
        res = process_single_domain(
            domain="example.com",
            engine=engine,
            record_types=[],
            show_dns_records=False,
        )

    engine.query_record.assert_not_called()
    rendered = mock_write.call_args[0][0]
    assert "[>] Target: example.com" in rendered
    assert "Resolves To     : 93.184.216.34 (edge.example.com)" in rendered
    assert "HTTP Status     : 200" in rendered
    assert "[>] DNS Records" not in rendered
    assert res["target"] == fake_target


def test_process_single_domain_shows_dns_table_with_t():
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
        "ptr": None,
        "resolves_to": "93.184.216.34",
        "http_status": 200,
    }

    with (
        patch("digger.gather_target_metadata", return_value=fake_target),
        patch("digger.tqdm.write") as mock_write,
    ):
        res = process_single_domain(
            domain="example.com",
            engine=engine,
            record_types=["A"],
            show_dns_records=True,
        )

    engine.query_record.assert_called_once_with("example.com", "A")
    rendered = mock_write.call_args[0][0]
    assert "[>] DNS Records (1 records found)" in rendered
    assert "93.184.216.34" in rendered
    assert res["total_records"] == 1
