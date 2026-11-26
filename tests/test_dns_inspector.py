from unittest.mock import MagicMock

from core.dns_inspector import inspect_dns_records_data


def test_inspect_dns_records_data_aggregates_records_and_providers():
    engine = MagicMock()

    def _query(domain: str, r_type: str):
        if r_type == "A":
            return {
                "status": "SUCCESS",
                "type": "A",
                "ttl": 300,
                "records": [{"value": "93.184.216.34", "priority": None}],
            }
        if r_type == "NS":
            return {
                "status": "SUCCESS",
                "type": "NS",
                "ttl": 86400,
                "records": [
                    {"value": "ns1.cloudflare.com", "priority": None},
                    {"value": "ns2.cloudflare.com", "priority": None},
                ],
            }
        if r_type == "MX":
            return {
                "status": "SUCCESS",
                "type": "MX",
                "ttl": 600,
                "records": [{"value": "aspmx.l.google.com", "priority": 1}],
            }
        return {"status": "NOERROR", "type": r_type, "records": []}

    engine.query_record.side_effect = _query

    res = inspect_dns_records_data(
        domain="example.com",
        engine=engine,
        record_types=["A", "NS", "MX"],
    )

    assert res["total_records"] == 4
    assert res["first_a_record"] == "93.184.216.34"
    assert res["dns_provider"] == "Cloudflare"
    assert res["email_provider"] == "Google Workspace"
    assert len(res["queries"]) == 3
    assert len(res["table_rows"]) == 4
