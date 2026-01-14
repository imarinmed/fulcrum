import os
from src.core.reporting import generate_standard_report


def test_large_dataset_generation(tmp_path, monkeypatch):
    import fulcrum.core.reporting as rep

    # Simulate large instance set across projects
    def fake_collect_all(sa_key_path=None):
        data = {}
        rows = [
            {
                "name": f"vm{i}",
                "machineType": "n2-standard-4",
                "zone": "us-central1-a",
                "status": "RUNNING",
                "creationTimestamp": "2025-01-01T00:00:00Z",
                "labels": {},
            }
            for i in range(20000)
        ]
        data["p1"] = {
            "instances": rows,
            "networks": [],
            "firewalls": [],
            "buckets": [],
            "sql_instances": [],
            "iam_policy": [{"bindings": []}],
        }
        return data

    monkeypatch.setattr(rep, "collect_all", fake_collect_all)
    res = generate_standard_report(
        str(tmp_path / "reports"), "PerfTester", report_date="20250101"
    )
    assert os.path.isfile(
        os.path.join(res["report_dir"], "projects", "virtual_machines.md")
    )
