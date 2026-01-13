from typing import List
import os
import subprocess
import csv
import shutil
import sys

def run_orchestrator(out_dir: str, cfg_path: str) -> None:
    env = dict(os.environ)
    tmpdir = os.path.join(out_dir, "tmp")
    os.makedirs(tmpdir, exist_ok=True)
    env["TMPDIR"] = tmpdir
    cmd = [sys.executable, os.path.join(out_dir, "scripts", "generate_catalog.py")]
    subprocess.run(cmd, check=True, env=env)

def read_csv(path: str) -> List[List[str]]:
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.reader(f))

def validate_csvs(out_dir: str) -> List[str]:
    issues: List[str] = []
    required = [
        os.path.join(out_dir, "csv", "compute.csv"),
        os.path.join(out_dir, "csv", "storage.csv"),
        os.path.join(out_dir, "access", "iam_matrix.csv"),
    ]
    for p in required:
        rows = read_csv(p)
        if not rows:
            issues.append(f"Missing or empty: {p}")
        else:
            header = rows[0]
            if "project_id" not in header:
                issues.append(f"Invalid header in {p}")
    return issues

def safe_copy_file(src: str, dst: str) -> None:
    if not src or not dst:
        return
    if os.path.exists(src):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)

def safe_copy_dir(src: str, dst: str) -> None:
    if not src or not dst:
        return
    if os.path.isdir(src):
        os.makedirs(dst, exist_ok=True)
        for root, _, files in os.walk(src):
            rel = os.path.relpath(root, src)
            target = os.path.join(dst, rel) if rel != "." else dst
            os.makedirs(target, exist_ok=True)
            for f in files:
                shutil.copy2(os.path.join(root, f), os.path.join(target, f))
