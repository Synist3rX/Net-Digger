from unittest.mock import MagicMock, patch

from core.formatters import INTERN_SEPARATOR_WIDTH, SEPARATOR_WIDTH, format_security_score_block
from core.security_score import evaluate_security_score, inspect_security_score


def test_evaluate_security_score_partial_grade_f():
    headers_payload = {
        "status": "SUCCESS",
        "all_headers": {
            "x-frame-options": "SAMEORIGIN",
            "server": "gws",
        },
    }

    result = evaluate_security_score(headers_payload)

    assert result["status"] == "SUCCESS"
    assert result["score"] == 15
    assert result["max_score"] == 95
    assert result["grade"] == "F"
    assert len(result["checks"]) == 6

    xfo = next(c for c in result["checks"] if c["header"] == "x-frame-options")
    hsts = next(c for c in result["checks"] if c["header"] == "strict-transport-security")

    assert xfo["present"] is True
    assert xfo["points"] == 15
    assert xfo["max_points"] == 15

    assert hsts["present"] is False
    assert hsts["points"] == 0
    assert hsts["max_points"] == 25
    assert "Not set" in hsts["status_text"]


def test_evaluate_security_score_high_grade_a():
    headers_payload = {
        "status": "SUCCESS",
        "all_headers": {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
        },
    }

    result = evaluate_security_score(headers_payload)

    # 25 + 25 + 15 + 10 + 10 = 85 / 95 (~89.47%) -> Grade A
    assert result["score"] == 85
    assert result["max_score"] == 95
    assert result["grade"] == "A"


def test_inspect_security_score_reuses_existing_headers():
    preloaded_headers = {
        "status": "SUCCESS",
        "all_headers": {"x-content-type-options": "nosniff"},
    }

    with patch("core.security_score.inspect_http_headers") as mock_http:
        result = inspect_security_score(
            target="example.com",
            http_headers_info=preloaded_headers,
        )

    mock_http.assert_not_called()
    assert result["status"] == "SUCCESS"
    assert result["score"] == 10
    assert result["grade"] == "F"


def test_inspect_security_score_fetches_headers_when_missing():
    fetched_headers = {
        "status": "SUCCESS",
        "all_headers": {"x-frame-options": "SAMEORIGIN"},
    }

    with patch("core.security_score.inspect_http_headers", return_value=fetched_headers) as mock_http:
        result = inspect_security_score(target="example.com", engine=MagicMock())

    mock_http.assert_called_once_with(target="example.com", engine=mock_http.call_args.kwargs["engine"])
    assert result["score"] == 15


def test_format_security_score_block_compact_and_full():
    score_data = {
        "status": "SUCCESS",
        "category": "HTTP Security Headers",
        "score": 15,
        "max_score": 95,
        "grade": "F",
        "checks": [
            {
                "header": "strict-transport-security",
                "label": "HSTS",
                "present": False,
                "value": None,
                "points": 0,
                "max_points": 25,
                "status_text": "Not set — site accessible over HTTP",
            },
            {
                "header": "x-frame-options",
                "label": "X-Frame-Options",
                "present": True,
                "value": "SAMEORIGIN",
                "points": 15,
                "max_points": 15,
                "status_text": "SAMEORIGIN",
            },
        ],
    }

    compact = "\n".join(format_security_score_block(score_data, full_output=False))
    assert ("-" * SEPARATOR_WIDTH) in compact
    assert ("    " + "-" * INTERN_SEPARATOR_WIDTH) in compact
    assert "[>] Security Score" in compact
    assert "Grade           : F" in compact
    assert "Points          : 15 / 95 points" in compact
    assert "15/15" in compact
    assert "0/25" in compact

    full = "\n".join(format_security_score_block(score_data, full_output=True))
    assert "Not set — site accessible over HTTP" in full
