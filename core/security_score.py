from typing import Any

from core.http_inspector import inspect_http_headers

HEADER_RULES: tuple[tuple[str, str, int, str], ...] = (
    (
        "strict-transport-security",
        "HSTS",
        25,
        "Not set — site accessible over HTTP",
    ),
    (
        "content-security-policy",
        "CSP",
        25,
        "Not set — no XSS/injection mitigation",
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        15,
        "Not set — clickjacking protection missing",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        10,
        "Not set — MIME sniffing allowed",
    ),
    (
        "referrer-policy",
        "Referrer-Policy",
        10,
        "Not set — full URLs sent as Referer",
    ),
    (
        "permissions-policy",
        "Permissions-Policy",
        10,
        "Not set — browser feature access unrestricted",
    ),
)

MAX_SECURITY_SCORE = sum(rule[2] for rule in HEADER_RULES)  # 95 points


def _compute_grade(score: int, max_score: int) -> str:
    if max_score <= 0:
        return "F"
    ratio = (score / max_score) * 100
    if ratio >= 85:
        return "A"
    if ratio >= 75:
        return "B"
    if ratio >= 60:
        return "C"
    if ratio >= 45:
        return "D"
    return "F"


def evaluate_security_score(
    http_headers_info: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Computes an HTTP Security Headers score (out of 95 points) and letter grade.
    """
    if not isinstance(http_headers_info, dict) or http_headers_info.get("status") != "SUCCESS":
        reason = (
            http_headers_info.get("message")
            if isinstance(http_headers_info, dict) and http_headers_info.get("message")
            else "HTTP headers data unavailable for security score."
        )
        return {
            "status": "ERROR",
            "message": reason,
            "score": 0,
            "max_score": MAX_SECURITY_SCORE,
            "grade": "F",
            "checks": [],
        }

    all_headers = http_headers_info.get("all_headers") or {}
    normalized_headers = {
        str(k).strip().lower(): str(v).strip()
        for k, v in all_headers.items()
        if v is not None
    }

    total_score = 0
    checks: list[dict[str, Any]] = []

    for header_key, label, max_pts, missing_msg in HEADER_RULES:
        raw_val = normalized_headers.get(header_key)
        present = bool(raw_val)
        earned = max_pts if present else 0
        total_score += earned

        checks.append(
            {
                "header": header_key,
                "label": label,
                "present": present,
                "value": raw_val if present else None,
                "points": earned,
                "max_points": max_pts,
                "status_text": raw_val if present else missing_msg,
            }
        )

    grade = _compute_grade(total_score, MAX_SECURITY_SCORE)

    return {
        "status": "SUCCESS",
        "category": "HTTP Security Headers",
        "score": total_score,
        "max_score": MAX_SECURITY_SCORE,
        "grade": grade,
        "checks": checks,
    }


def inspect_security_score(
    target: str,
    engine: Any = None,
    http_headers_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluates the security score for a target, reusing pre-fetched HTTP headers if provided.
    """
    headers_data = http_headers_info
    if headers_data is None:
        headers_data = inspect_http_headers(target=target, engine=engine)
    return evaluate_security_score(headers_data)
