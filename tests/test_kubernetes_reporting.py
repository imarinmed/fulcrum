import os
import sys


def test_kubernetes_section_in_report(tmp_path, monkeypatch):
    from fulcrum.core.reporting import generate_standard_report
    import src.core.reporting as rep

    def fake_collect_all(sa_key_path=None):
        return {
            "p1": {
                "instances": [],
                "networks": [],
                "firewalls": [],
                "buckets": [],
                "sql_instances": [],
                "iam_policy": [],
                "gke_clusters": [
                    {
                        "name": "p1-us-central1-c1",
                        "location": "us-central1",
                        "currentMasterVersion": "1.29.3",
                        "network": "default",
                        "subnetwork": "default",
                        "labels": {"env": "dev"},
                    }
                ],
            }
        }

    monkeypatch.setattr(rep, "collect_all", fake_collect_all)
    res = generate_standard_report(
        str(tmp_path / "reports"), "Tester", report_date="20250101"
    )
    k_path = os.path.join(res["report_dir"], "projects", "kubernetes.md")
    assert os.path.exists(k_path)
    with open(k_path) as f:
        content = f.read()
    assert "Kubernetes" in content and "p1-us-central1-c1" in content
