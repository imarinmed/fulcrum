import json
import os
import sys

def test_generate_kubernetes_csv_from_raw(tmp_path):
    out_dir = tmp_path.as_posix()
    raw_dir = os.path.join(out_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    assets = [
        {
            "assetType": "container.googleapis.com/Cluster",
            "name": "projects/test/locations/us-central1/clusters/test-cluster",
            "resource": {
                "data": {
                    "location": "us-central1",
                    "currentMasterVersion": "1.29.3",
                    "network": "default",
                    "subnetwork": "default",
                    "labels": {"env": "dev"},
                }
            },
        }
    ]
    with open(os.path.join(raw_dir, "test_assets.json"), "w") as f:
        json.dump(assets, f)
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from src.core.docs import generate_kubernetes_csv, read_csv
    path = generate_kubernetes_csv(out_dir)
    assert os.path.exists(path)
    rows = read_csv(path)
    assert rows and rows[0].get("project_id") == "test"
