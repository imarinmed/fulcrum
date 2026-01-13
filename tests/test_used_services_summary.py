import json
import os
import sys

def test_generate_used_services_summary(tmp_path):
    out_dir = tmp_path.as_posix()
    raw_dir = os.path.join(out_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    assets = [
        {"assetType": "container.googleapis.com/Cluster"},
        {"assetType": "run.googleapis.com/Service"},
        {"assetType": "run.googleapis.com/Service"},
        {"assetType": "compute.googleapis.com/Instance"},
    ]
    with open(os.path.join(raw_dir, "demo_assets.json"), "w") as f:
        json.dump(assets, f)
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from src.core.docs import generate_used_services_summary
    rel = generate_used_services_summary(out_dir)
    path = os.path.join(out_dir, "executive", rel)
    assert os.path.exists(path)
    with open(path) as f:
        content = f.read()
    assert "Used Services Summary" in content
    assert "GKE Clusters" in content
    assert "Cloud Run Services" in content
