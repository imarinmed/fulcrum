import os
import re
import json
from typing import List

def _required_pages() -> List[str]:
    return [
        "compute.md",
        "data_storage.md",
        "data_analytics.md",
        "networking.md",
        "security.md",
        "serverless.md",
        "virtual_machines.md",
        "storage.md",
        "buckets.md",
    ]

def validate_structure(report_dir: str) -> List[str]:
    issues: List[str] = []
    if not os.path.isdir(report_dir):
        issues.append("report_dir missing")
        return issues
    if not os.path.isfile(os.path.join(report_dir, "index.md")):
        issues.append("index.md missing")
    if not os.path.isfile(os.path.join(report_dir, "metadata.json")):
        issues.append("metadata.json missing")
    proj_dir = os.path.join(report_dir, "projects")
    if not os.path.isdir(proj_dir):
        issues.append("projects directory missing")
        return issues
    for fn in _required_pages():
        if not os.path.isfile(os.path.join(proj_dir, fn)):
            issues.append(f"missing {fn}")
    return issues

def validate_tables(path: str) -> List[str]:
    issues: List[str] = []
    if not os.path.isfile(path):
        return issues
    with open(path, "r") as f:
        content = f.read()
    tables = re.findall(r"(^\| .*\|\n\| .*\|(?:\n\| .*\|)+)", content, re.MULTILINE)
    for t in tables:
        lines = t.strip().split("\n")
        header_cols = lines[0].count("|")
        sep_cols = lines[1].count("|")
        if header_cols != sep_cols:
            issues.append(f"table separator mismatch in {os.path.basename(path)}")
        for i in range(2, len(lines)):
            if lines[i].count("|") != header_cols:
                issues.append(f"row column count mismatch in {os.path.basename(path)}")
    return issues

def validate_headers(path: str) -> List[str]:
    issues: List[str] = []
    if not os.path.isfile(path):
        return issues
    with open(path, "r") as f:
        lines = f.readlines()
    has_h2 = any(l.startswith("## ") for l in lines)
    if not has_h2:
        issues.append(f"missing H2 header in {os.path.basename(path)}")
    return issues

def validate_links(report_dir: str) -> List[str]:
    issues: List[str] = []
    index = os.path.join(report_dir, "index.md")
    if not os.path.isfile(index):
        return ["index.md missing"]
    with open(index, "r") as f:
        content = f.read()
    for m in re.finditer(r"\[.*?\]\((.*?)\)", content):
        target = os.path.normpath(os.path.join(report_dir, m.group(1)))
        if not os.path.exists(target):
            issues.append(f"broken link: {m.group(1)}")
    return issues

def validate_metadata(report_dir: str) -> List[str]:
    issues: List[str] = []
    path = os.path.join(report_dir, "metadata.json")
    if not os.path.isfile(path):
        return ["metadata.json missing"]
    try:
        with open(path, "r") as f:
            meta = json.load(f)
        ts = meta.get("generated_at", "")
        if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$", ts):
            issues.append("invalid generated_at timestamp")
    except Exception:
        issues.append("metadata.json unreadable")
    return issues

def validate_report(report_dir: str) -> List[str]:
    issues = []
    issues += validate_structure(report_dir)
    proj = os.path.join(report_dir, "projects")
    for fn in _required_pages():
        p = os.path.join(proj, fn)
        issues += validate_tables(p)
        issues += validate_headers(p)
    # Security page should include Prowler section if prowler data exists
    data_dir = os.path.join(report_dir, "data")
    if os.path.isdir(data_dir) and (os.path.isfile(os.path.join(data_dir, "prowler.json")) or os.path.isfile(os.path.join(data_dir, "prowler.csv"))):
        sec = os.path.join(proj, "security.md")
        if os.path.isfile(sec):
            with open(sec, "r") as f:
                content = f.read()
            if "Prowler Assessments" not in content:
                issues.append("security.md missing Prowler section")
    issues += validate_links(report_dir)
    issues += validate_metadata(report_dir)
    return issues
