import os
import json
import time
from typing import Dict, Any, List

def now() -> float:
    return time.time()

def ensure_file(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump({"projects": {}}, f)

def read_state(path: str) -> Dict[str, Any]:
    ensure_file(path)
    with open(path, "r") as f:
        return json.load(f)

def write_state(path: str, state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(state, f)

def init_projects(path: str, projects: List[str], phases: List[str]) -> None:
    st = {"projects": {}}
    t = now()
    for p in projects:
        st["projects"][p] = {
            "start": t,
            "phases": {ph: {"start": 0.0, "progress": 0.0, "eta": "--", "elapsed": 0.0, "status": "pending"} for ph in phases},
            "summary": {"avg_eta": "--", "completion": 0.0}
        }
    write_state(path, st)

def update_phase(path: str, project: str, phase: str, progress: float, status: str) -> None:
    st = read_state(path)
    proj = st["projects"].setdefault(project, {"phases": {}, "summary": {}})
    ph = proj["phases"].setdefault(phase, {})
    if ph.get("start", 0.0) == 0.0:
        ph["start"] = now()
    ph["progress"] = max(0.0, min(100.0, progress))
    el = now() - ph["start"]
    ph["elapsed"] = el
    remaining = max(0.0, 100.0 - ph["progress"]) / max(1e-3, ph["progress"]) * el if ph["progress"] > 0 else 0.0
    h = int(remaining // 3600)
    m = int((remaining % 3600) // 60)
    ph["eta"] = f"{h}:{m:02d}"
    ph["status"] = status
    proj["phases"][phase] = ph
    comp = sum(p.get("progress", 0.0) for p in proj["phases"].values()) / max(1, len(proj["phases"]))
    proj["summary"]["completion"] = comp
    write_state(path, st)
