import socket
import urllib.error
from unittest.mock import MagicMock, patch

from core.target_inspector import gather_target_metadata


def test_gather_target_metadata_with_engine_and_ptr():
    """Usa el motor DNS para A y PTR sin alterar el timeout global de socket."""
    engine = MagicMock()

    def _query(qname: str, r_type: str):
        if r_type == "A" and qname == "example.com":
            return {
                "status": "SUCCESS",
                "type": "A",
                "records": [{"value": "93.184.216.34", "priority": None}],
            }
        if r_type == "PTR" and qname == "34.216.184.93.in-addr.arpa":
            return {
                "status": "SUCCESS",
                "type": "PTR",
                "records": [{"value": "edge.example.com.", "priority": None}],
            }
        return {"status": "NXDOMAIN", "type": r_type, "records": []}

    engine.query_record.side_effect = _query

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False

    original_timeout = socket.getdefaulttimeout()

    with patch("core.target_inspector.urllib.request.urlopen", return_value=mock_resp):
        meta = gather_target_metadata("Example.COM.", engine, timeout=3.0)

    assert socket.getdefaulttimeout() == original_timeout
    assert meta["query"] == "example.com"
    assert meta["ip"] == "93.184.216.34"
    assert meta["ptr"] == "edge.example.com"
    assert meta["resolves_to"] == "93.184.216.34 (edge.example.com)"
    assert meta["http_status"] == 200


def test_gather_target_metadata_http_405_fallback_to_get_and_ip_only():
    """Si HEAD devuelve 405 reintenta con GET; sin PTR muestra solo la IP."""
    engine = MagicMock()
    engine.query_record.return_value = {"status": "NXDOMAIN", "type": "A", "records": []}

    mock_ok = MagicMock()
    mock_ok.status = 200
    mock_ok.__enter__.return_value = mock_ok
    mock_ok.__exit__.return_value = False

    http_405 = urllib.error.HTTPError(
        url="https://example.org",
        code=405,
        msg="Method Not Allowed",
        hdrs=None,
        fp=None,
    )

    def _urlopen(req, timeout=4.0):
        if req.get_method() == "HEAD":
            raise http_405
        return mock_ok

    with (
        patch("core.target_inspector.socket.gethostbyname", return_value="198.51.100.25"),
        patch("core.target_inspector.socket.getnameinfo", side_effect=OSError("no ptr")),
        patch("core.target_inspector.urllib.request.urlopen", side_effect=_urlopen),
    ):
        meta = gather_target_metadata("example.org", engine, timeout=2.0)

    assert meta["ip"] == "198.51.100.25"
    assert meta["ptr"] is None
    assert meta["resolves_to"] == "198.51.100.25"
    assert meta["http_status"] == 200


def test_gather_target_metadata_unreachable_http_and_no_ip():
    """Devuelve N/A en resolves_to y http_status cuando no hay resolución ni respuesta HTTP."""
    engine = MagicMock()
    engine.query_record.return_value = {"status": "NXDOMAIN", "type": "A", "records": []}

    with (
        patch("core.target_inspector.socket.gethostbyname", side_effect=OSError("fail")),
        patch("core.target_inspector.urllib.request.urlopen", side_effect=OSError("timeout")),
    ):
        meta = gather_target_metadata("offline.test", engine, timeout=1.0)

    assert meta["ip"] is None
    assert meta["ptr"] is None
    assert meta["resolves_to"] == "N/A"
    assert meta["http_status"] == "N/A"
