from typing import Any, Dict, List
import os
import yaml

def load_yaml(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

def write_yaml(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(data, f)

def merge_config_projects(cfg: Dict[str, Any], org_id: str, projects: List[str], redact: bool) -> Dict[str, Any]:
    res = dict(cfg)
    res["org_id"] = org_id
    res["projects"] = projects
    red = res.get("redaction", {})
    red["enabled"] = bool(redact)
    res["redaction"] = red
    return res
