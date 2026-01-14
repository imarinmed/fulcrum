import json
import os

from src.core.reporting import generate_standard_report


def test_security_outputs_include_all_canonical_fields(tmp_path, monkeypatch):
    import fulcrum.core.reporting as rep

    def fake_collect_all(sa_key_path=None):
        return {
            "p1": {
                "instances": [],
                "networks": [],
                "firewalls": [],
                "buckets": [],
                "sql_instances": [],
                "iam_policy": [{"bindings": []}],
            }
        }

    monkeypatch.setattr(rep, "collect_all", fake_collect_all)
    pdata = tmp_path / "prowler.json"
    pdata.write_text(
        json.dumps(
            [
                {
                    "check_id": "gcp_storage_bucket_public",
                    "service": "gcs",
                    "status": "FAIL",
                    "severity": "high",
                    "resource_id": "b1",
                    "project_id": "p1",
                    "description": "Bucket is public",
                    "remediation": "Make it private",
                    "category": "DataProtection",
                    "evidence": "ACL: allUsers",
                }
            ]
        )
    )
    res = generate_standard_report(
        str(tmp_path / "reports"),
        "Tester",
        report_date="20250101",
        prowler_json=str(pdata),
    )
    sec_json = os.path.join(res["report_dir"], "data", "security.json")
    assert os.path.isfile(sec_json)
    items = json.loads(open(sec_json).read())
    assert items and isinstance(items, list)
    i = items[0]
    for key in [
        "project_id",
        "resource_id",
        "check_id",
        "service",
        "status",
        "severity",
        "framework",
        "description",
        "recommendation",
        "category",
        "evidence",
    ]:
        assert key in i
    # CSV subset exists
    sec_csv = os.path.join(res["report_dir"], "data", "security.csv")
    assert os.path.isfile(sec_csv)
    csv_text = open(sec_csv).read().strip().splitlines()
    assert csv_text[0].split(",") == [
        "project_id",
        "resource_id",
        "check_id",
        "service",
        "severity",
        "status",
        "framework",
    ]
