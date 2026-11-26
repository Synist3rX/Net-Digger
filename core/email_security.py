import re
from core.resolver import DNSResolverEngine


COMMON_DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mx",
    "mail",
    "dkim",
    "amazonses",
    "mandrill",
    "sendgrid",
    "zoho",
    "protonmail",
)

SPF_LOOKUP_MECH_RE = re.compile(
    r"^(?:[+\-~?])?(?:include:|a(?::|/.+)?$|mx(?::|/.+)?$|ptr(?::|/.+)?$|exists:|redirect=)",
    re.IGNORECASE,
)


def _get_txt_values(engine: DNSResolverEngine, qname: str) -> list[str]:
    res = engine.query_record(qname, "TXT")
    if not isinstance(res, dict) or res.get("status") != "SUCCESS":
        return []
    return [
        str(rec.get("value", "")).strip()
        for rec in res.get("records", [])
        if str(rec.get("value", "")).strip()
    ]


def _classify_spf_policy(spf_record: str) -> str:
    tokens = spf_record.split()
    for token in reversed(tokens):
        low = token.lower()
        if low == "~all":
            return "Soft Fail (~all)"
        if low == "-all":
            return "Fail (-all)"
        if low == "?all":
            return "Neutral (?all)"
        if low == "+all":
            return "Pass (+all)"
    return "Configured"


def _count_spf_lookups(
    engine: DNSResolverEngine,
    domain: str,
    visited: set[str] | None = None,
    depth: int = 0,
) -> int:
    if visited is None:
        visited = set()
    norm = domain.lower().rstrip(".")
    if norm in visited or depth > 10:
        return 0
    visited.add(norm)

    txt_list = _get_txt_values(engine, norm)
    spf_records = [t for t in txt_list if t.lower().startswith("v=spf1")]
    if not spf_records:
        return 0

    lookups = 0
    for rec in spf_records:
        for token in rec.split()[1:]:
            if SPF_LOOKUP_MECH_RE.match(token):
                lookups += 1
                low_tok = token.lower()
                if low_tok.startswith("include:"):
                    target = token.split(":", 1)[1].strip()
                    lookups += _count_spf_lookups(engine, target, visited, depth + 1)
                elif low_tok.startswith("redirect="):
                    target = token.split("=", 1)[1].strip()
                    lookups += _count_spf_lookups(engine, target, visited, depth + 1)
    return lookups


def _parse_dmarc_tags(dmarc_record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in dmarc_record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def inspect_email_security(
    domain: str,
    engine: DNSResolverEngine,
    dkim_selectors: tuple[str, ...] | list[str] = COMMON_DKIM_SELECTORS,
) -> dict:
    """
    Audits SPF, DMARC, and common DKIM selectors for a target domain.
    """
    clean_domain = domain.strip().lower().rstrip(".")

    # 1. SPF
    root_txt = _get_txt_values(engine, clean_domain)
    spf_records = [t for t in root_txt if re.match(r"^v=spf1(?:\s|$)", t, re.IGNORECASE)]
    spf_record = spf_records[0] if spf_records else None

    if spf_record:
        spf_status = _classify_spf_policy(spf_record)
        spf_lookups = _count_spf_lookups(engine, clean_domain)
        spf_info = {
            "found": True,
            "status": spf_status,
            "lookups": spf_lookups,
            "max_lookups": 10,
            "record": spf_record,
        }
    else:
        spf_info = {
            "found": False,
            "status": "Missing",
            "lookups": 0,
            "max_lookups": 10,
            "record": None,
        }

    # 2. DMARC
    dmarc_qname = f"_dmarc.{clean_domain}"
    dmarc_txt = _get_txt_values(engine, dmarc_qname)
    dmarc_records = [t for t in dmarc_txt if re.match(r"^v=dmarc1(?:\s*;|\s*$)", t, re.IGNORECASE)]
    dmarc_record = dmarc_records[0] if dmarc_records else None

    if dmarc_record:
        tags = _parse_dmarc_tags(dmarc_record)
        policy = tags.get("p", "none").lower()
        rua = tags.get("rua")
        ruf = tags.get("ruf")
        report_target = rua.split(",")[0].strip() if rua else (ruf.split(",")[0].strip() if ruf else None)
        dmarc_info = {
            "found": True,
            "policy": policy,
            "reports": report_target,
            "record": dmarc_record,
        }
    else:
        dmarc_info = {
            "found": False,
            "policy": None,
            "reports": None,
            "record": None,
        }

    # 3. DKIM (selectores comunes)
    found_selectors: list[dict[str, str]] = []
    for selector in dkim_selectors:
        sel_clean = selector.strip()
        if not sel_clean:
            continue
        dkim_qname = f"{sel_clean}._domainkey.{clean_domain}"
        dkim_txt = _get_txt_values(engine, dkim_qname)
        if dkim_txt:
            found_selectors.append({
                "selector": sel_clean,
                "record": " ".join(dkim_txt),
            })

    if found_selectors:
        dkim_info = {
            "found": True,
            "status": "Detected",
            "selectors": [s["selector"] for s in found_selectors],
            "records": found_selectors,
            "detail": f"Found selectors: {', '.join(s['selector'] for s in found_selectors)}",
        }
    else:
        dkim_info = {
            "found": False,
            "status": "Not detected",
            "selectors": [],
            "records": [],
            "detail": "No selectors found from common list",
        }

    # Resumen general
    present_count = sum([
        1 if spf_info["found"] else 0,
        1 if dmarc_info["found"] else 0,
        1 if dkim_info["found"] else 0,
    ])
    if present_count == 0:
        overall_status = "Missing"
    elif (
        spf_info["found"]
        and dmarc_info["found"]
        and dkim_info["found"]
        and dmarc_info["policy"] in ("reject", "quarantine")
        and spf_info["status"].startswith("Fail")
    ):
        overall_status = "Strong"
    else:
        overall_status = "Partial"

    return {
        "status": "SUCCESS",
        "domain": clean_domain,
        "overall_status": overall_status,
        "spf": spf_info,
        "dmarc": dmarc_info,
        "dkim": dkim_info,
    }
