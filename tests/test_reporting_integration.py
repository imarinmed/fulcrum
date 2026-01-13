import os
import json
from ..src.core.reporting import generate_standard_report
from ..src.core.validator import validate_report

def _write_csv(dirpath, name, headers, rows):
    os.makedirs(os.path.join(dirpath, "csv"), exist_ok=True)
    p = os.path.join(dirpath, "csv", name)
    with open(p, "w") as f:
        f.write(",".join(headers) + "\n")
        for r in rows:
            f.write(",".join(r) + "\n")

def _write_raw(dirpath, pid, assets):
    os.makedirs(os.path.join(dirpath, "raw"), exist_ok=True)
    p = os.path.join(dirpath, "raw", f"{pid}_assets.json")
    with open(p, "w") as f:
        json.dump(assets, f)

def test_generate_and_validate(tmp_path, monkeypatch):
    # Monkeypatch collectors to return deterministic data
    import fulcrum.core.reporting as rep
    def fake_collect_all(sa_key_path=None):
        return {
            "p1": {
                "instances": [{"name":"vm1","machineType":"n2-standard-4","zone":"us-central1-a","status":"RUNNING","creationTimestamp":"2025-01-01T00:00:00Z","labels":{}}],
                "networks": [{"name":"net1","autoCreateSubnetworks": False}],
                "firewalls": [{"name":"fw1","network":"net1","direction":"INGRESS","priority":1000}],
                "buckets": [{"name":"b1","location":"US","storageClass":"STANDARD","labels":{"env":"prod"}}],
                "sql_instances": [{"name":"sql1","databaseVersion":"POSTGRES_15","region":"us-central","gceZone":"us-central1-a"}],
                "iam_policy": [{"bindings":[]}],
            }
        }
    monkeypatch.setattr(rep, "collect_all", fake_collect_all)
    # Generate and validate
    # Create a sample prowler JSON
    pdata = tmp_path / "prowler.json"
    pdata.write_text('[{"check_id":"gcp_compute_firewall_open","service":"compute","status":"FAIL","resource_id":"fw1","project_id":"p1","severity":"high"}]')
    res = generate_standard_report(str(tmp_path / "reports"), "Tester", report_date="20250101", prowler_json=str(pdata))
    issues = validate_report(res["report_dir"])
    assert not issues
