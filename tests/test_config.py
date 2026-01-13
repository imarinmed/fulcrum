from ..src.core.config import merge_config_projects

def test_merge_projects():
    cfg = {"org_id": "x", "projects": ["a"], "redaction": {"enabled": False}}
    res = merge_config_projects(cfg, "y", ["b","c"], True)
    assert res["org_id"] == "y"
    assert res["projects"] == ["b","c"]
    assert res["redaction"]["enabled"] is True
