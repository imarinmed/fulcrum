import os
import json
import csv
import sys
import platform
import glob
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
import structlog

from .. import __version__
from .markdown import header, table, link, escape
from .collect import collect_all
from ..prowler.parser import parse as parse_prowler
from ..prowler.normalize import to_canonical as normalize_prowler

log = structlog.get_logger()


class SystemSnapshot:
    """Captures the system state at the time of reporting."""

    def __init__(self, settings_dump: Dict[str, Any]):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.platform = platform.platform()
        self.python_version = sys.version
        self.fulcrum_version = __version__
        self.settings = settings_dump
        # Could add pip freeze or other env info here

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "platform": self.platform,
            "python_version": self.python_version,
            "fulcrum_version": self.fulcrum_version,
            "settings": self.settings,
        }


class HistoryManager:
    """Manages historical report data for trend analysis."""

    def __init__(self, base_dir: str = "reports"):
        self.base_dir = base_dir

    def get_history(self) -> List[Dict[str, Any]]:
        """Retrieves metadata from all past reports."""
        history = []
        # Look for metadata.json in report-* directories
        pattern = os.path.join(self.base_dir, "report-*", "metadata.json")
        for meta_path in glob.glob(pattern):
            try:
                with open(meta_path, "r") as f:
                    data = json.load(f)
                    # Enrich with directory name if needed
                    data["_path"] = os.path.dirname(meta_path)
                    history.append(data)
            except Exception as e:
                log.warning("history.load_error", path=meta_path, error=str(e))

        # Sort by generated_at
        history.sort(key=lambda x: x.get("generated_at", ""), reverse=True)
        return history

    def get_trends(self) -> Dict[str, Any]:
        """Computes basic trends from history."""
        history = self.get_history()
        trends = {"report_count": len(history), "dates": [], "project_counts": []}
        for h in history:
            trends["dates"].append(h.get("generated_at"))
            # Example metric: number of projects
            projects = h.get("projects", [])
            trends["project_counts"].append(len(projects))
        return trends


def _is_safe_base(base: str) -> bool:
    parts = os.path.normpath(base).split(os.sep)
    return ".." not in parts


def _sanitize_rtype(rtype: Optional[str]) -> str:
    t = (rtype or "std").lower()
    if t not in {"std", "sec"}:
        raise ValueError("Invalid report type")
    return t


def _compute_report_dir_name(base: str, rtype: str, date_str: str) -> str:
    return os.path.join(base, f"report-{rtype}-{date_str}")


def _resolve_duplicate_dir(path: str) -> str:
    if not os.path.isdir(path):
        return path
    # If directory exists and is non-empty, append numeric suffix
    suffix = 2
    while True:
        candidate = f"{path}-{suffix:02d}"
        if not os.path.exists(candidate):
            return candidate
        suffix += 1


def ensure_report_dir(
    out_base: Optional[str],
    report_date: Optional[str] = None,
    rtype: Optional[str] = "std",
) -> str:
    base = out_base or "reports"
    if not _is_safe_base(base):
        raise ValueError("Invalid base path")
    date_str = report_date or datetime.now(timezone.utc).strftime("%Y%m%d")
    t = _sanitize_rtype(rtype)
    parent = _compute_report_dir_name(base, t, date_str)
    # Handle duplicate directory names
    if os.path.isdir(parent):
        # consider non-empty directory a collision
        try:
            if any(True for _ in os.scandir(parent)):
                parent = _resolve_duplicate_dir(parent)
        except Exception:
            parent = _resolve_duplicate_dir(parent)
    os.makedirs(parent, exist_ok=True)
    os.makedirs(os.path.join(parent, "projects"), exist_ok=True)
    return parent


def _read_csv(path: str) -> Tuple[List[str], List[List[str]]]:
    if not os.path.exists(path):
        return [], []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        headers = list(reader.fieldnames or [])
        rows: List[List[str]] = []
        for r in reader:
            rows.append([str(r.get(h, "")) for h in headers])
        return headers, rows


def _write_md(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def _page_from_csv(
    report_dir: str, name: str, csv_path: str, h2: str, h3: Optional[str] = None
) -> str:
    headers, rows = _read_csv(csv_path)
    content = header(2, h2)
    if h3:
        content += header(3, h3)
    if headers:
        content += table(headers, rows)
    else:
        content += "No data available\n"
    p = os.path.join(report_dir, "projects", f"{name}.md")
    _write_md(p, content)
    return p


def build_projects_from_data(report_dir: str, data: Dict[str, Dict]) -> Dict[str, str]:
    paths: Dict[str, str] = {}
    # Virtual Machines / Compute
    headers_vm = [
        "project_id",
        "name",
        "machineType",
        "zone",
        "status",
        "creationTimestamp",
        "labels",
    ]
    vm_rows: List[List[str]] = []
    for pid, pdata in data.items():
        for inst in pdata.get("instances", []):
            vm_rows.append(
                [
                    pid,
                    inst.get("name", ""),
                    inst.get("machineType", ""),
                    inst.get("zone", ""),
                    inst.get("status", ""),
                    inst.get("creationTimestamp", ""),
                    ",".join(
                        [f"{k}:{v}" for k, v in (inst.get("labels") or {}).items()]
                    ),
                ]
            )
    _p_vm = os.path.join(report_dir, "projects", "virtual_machines.md")
    content_vm = header(2, "Virtual Machines") + table(headers_vm, vm_rows)
    _write_md(_p_vm, content_vm)
    paths["virtual_machines"] = _p_vm
    _p_compute = os.path.join(report_dir, "projects", "compute.md")
    _write_md(_p_compute, content_vm)
    paths["compute"] = _p_compute
    # Networking
    headers_net = ["project_id", "name", "autoCreateSubnetworks"]
    net_rows: List[List[str]] = []
    for pid, pdata in data.items():
        for n in pdata.get("networks", []):
            net_rows.append(
                [pid, n.get("name", ""), str(n.get("autoCreateSubnetworks", ""))]
            )
    _p = os.path.join(report_dir, "projects", "networking.md")
    _write_md(_p, header(2, "Networking") + table(headers_net, net_rows))
    paths["networking"] = _p
    # Firewalls
    headers_fw = ["project_id", "name", "network", "direction", "priority"]
    fw_rows: List[List[str]] = []
    for pid, pdata in data.items():
        for fw in pdata.get("firewalls", []):
            fw_rows.append(
                [
                    pid,
                    fw.get("name", ""),
                    fw.get("network", ""),
                    fw.get("direction", ""),
                    str(fw.get("priority", "")),
                ]
            )
    _p = os.path.join(report_dir, "projects", "security.md")
    _write_md(_p, header(2, "Security") + table(headers_fw, fw_rows))
    paths["security"] = _p
    # Prowler section appended if available
    prowler_dir = os.path.join(report_dir, "data")
    prowler_json = os.path.join(prowler_dir, "prowler.json")
    prowler_csv = os.path.join(prowler_dir, "prowler.csv")
    prowler_items: List[Dict] = []
    prowler_inputs: List[tuple] = []
    if os.path.isfile(prowler_json):
        prowler_inputs.append(("json", prowler_json))
    if os.path.isfile(prowler_csv):
        prowler_inputs.append(("csv", prowler_csv))
    if prowler_inputs:
        prowler_items = normalize_prowler(parse_prowler(prowler_inputs))
        headers_p = [
            "project_id",
            "resource_id",
            "check_id",
            "service",
            "severity",
            "status",
            "framework",
        ]
        rows_p = [[i.get(h, "") for h in headers_p] for i in prowler_items]
        sec_path = os.path.join(report_dir, "projects", "security.md")
        content = (
            header(2, "Security")
            + table(headers_fw, fw_rows)
            + header(3, "Prowler Assessments")
            + table(headers_p, rows_p)
        )
        _write_md(sec_path, content)
        paths["security"] = sec_path
        with open(os.path.join(prowler_dir, "security.json"), "w") as f:
            json.dump(prowler_items, f, indent=2)
        import csv as _csv

        with open(os.path.join(prowler_dir, "security.csv"), "w", newline="") as f:
            w = _csv.DictWriter(f, fieldnames=headers_p)
            w.writeheader()
            for r in prowler_items:
                w.writerow({k: r.get(k, "") for k in headers_p})
    # Buckets
    headers_b = ["project_id", "name", "location", "storageClass", "labels"]
    b_rows: List[List[str]] = []
    for pid, pdata in data.items():
        for b in pdata.get("buckets", []):
            b_rows.append(
                [
                    pid,
                    b.get("name", ""),
                    b.get("location", ""),
                    b.get("storageClass", ""),
                    ",".join([f"{k}:{v}" for k, v in (b.get("labels") or {}).items()]),
                ]
            )
    _p_buckets = os.path.join(report_dir, "projects", "buckets.md")
    content_b = header(2, "Buckets") + table(headers_b, b_rows)
    _write_md(_p_buckets, content_b)
    paths["buckets"] = _p_buckets
    # Data Storage (Cloud SQL)
    headers_ds = ["project_id", "name", "databaseVersion", "region", "gceZone"]
    ds_rows: List[List[str]] = []
    for pid, pdata in data.items():
        for sql in pdata.get("sql_instances", []):
            ds_rows.append(
                [
                    pid,
                    sql.get("name", ""),
                    sql.get("databaseVersion", ""),
                    sql.get("region", ""),
                    sql.get("gceZone", ""),
                ]
            )
    _p_ds = os.path.join(report_dir, "projects", "data_storage.md")
    _write_md(_p_ds, header(2, "Data Storage Services") + table(headers_ds, ds_rows))
    paths["data_storage"] = _p_ds
    _p_storage = os.path.join(report_dir, "projects", "storage.md")
    _write_md(_p_storage, content_b)
    paths["storage"] = _p_storage
    # Kubernetes (GKE Clusters)
    headers_k = [
        "project_id",
        "name",
        "location",
        "currentMasterVersion",
        "network",
        "subnetwork",
        "labels",
    ]
    k_rows: List[List[str]] = []
    for pid, pdata in data.items():
        for c in pdata.get("gke_clusters", []):
            labels = c.get("labels") or c.get("resourceLabels") or {}
            k_rows.append(
                [
                    pid,
                    c.get("name", ""),
                    c.get("location", ""),
                    c.get("currentMasterVersion", ""),
                    c.get("network", ""),
                    c.get("subnetwork", ""),
                    ",".join([f"{k}:{v}" for k, v in (labels or {}).items()]),
                ]
            )
    _p_k = os.path.join(report_dir, "projects", "kubernetes.md")
    _write_md(_p_k, header(2, "Kubernetes") + table(headers_k, k_rows))
    paths["kubernetes"] = _p_k
    # Serverless / Data Analytics placeholders (extend later if enabled)
    for name, title in [
        ("serverless", "Serverless"),
        ("data_analytics", "Analytics Services"),
    ]:
        _p = os.path.join(report_dir, "projects", f"{name}.md")
        _write_md(_p, header(2, title) + "No data available\n")
        paths[name] = _p
    return paths


def write_index(report_dir: str, page_paths: Dict[str, str], author: str) -> str:
    lines: List[str] = []
    lines.append(header(2, "Report Overview"))
    lines.append(f"Author: {escape(author)}\n\n")
    lines.append(header(3, "Contents"))
    for name in [
        "compute",
        "data_storage",
        "data_analytics",
        "networking",
        "kubernetes",
        "security",
        "serverless",
        "virtual_machines",
        "storage",
        "buckets",
    ]:
        if name in page_paths:
            rel = os.path.relpath(page_paths[name], report_dir)
            lines.append(f"- {link(name.replace('_', ' ').title(), rel)}")
    content = "".join(lines)
    path = os.path.join(report_dir, "index.md")
    _write_md(path, content)
    return path


def write_metadata(report_dir: str, report_version: str) -> str:
    s = load_settings(None)
    snapshot = SystemSnapshot(s.model_dump())
    meta = {
        "generated_at": snapshot.timestamp,
        "report_version": report_version,
        "org_id": s.org.org_id,
        "projects": s.catalog.projects,
        "system_snapshot": snapshot.to_dict(),
    }
    path = os.path.join(report_dir, "metadata.json")
    with open(path, "w") as f:
        json.dump(meta, f, indent=2)
    return path


def generate_standard_report(
    out_base: Optional[str],
    author: str,
    report_date: Optional[str] = None,
    report_version: str = "1.0.0",
    sa_key_path: Optional[str] = None,
    prowler_json: Optional[str] = None,
    prowler_csv: Optional[str] = None,
    rtype: Optional[str] = "std",
) -> Dict[str, str]:
    log.info("report.init", out_base=out_base)
    report_dir = ensure_report_dir(out_base, report_date, rtype)
    data = collect_all(sa_key_path)
    data_dir = os.path.join(report_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    if prowler_json and os.path.isfile(prowler_json):
        with open(os.path.join(data_dir, "prowler.json"), "w") as f:
            f.write(open(prowler_json, "r").read())
    if prowler_csv and os.path.isfile(prowler_csv):
        with open(os.path.join(data_dir, "prowler.csv"), "w") as f:
            f.write(open(prowler_csv, "r").read())
    pages = build_projects_from_data(report_dir, data)
    # Also emit machine-readable JSON per project
    with open(os.path.join(data_dir, "resources.json"), "w") as f:
        json.dump(data, f, indent=2)
    index_path = write_index(report_dir, pages, author)
    meta_path = write_metadata(report_dir, report_version)
    log.info("report.complete", report_dir=report_dir)
    return {
        "report_dir": report_dir,
        "index": index_path,
        "metadata": meta_path,
        **pages,
    }
