import os
import json
import csv
from datetime import datetime
from typing import Dict, List, Optional
import structlog

from .markdown import table

log = structlog.get_logger()


def ensure_exec_dir(out_dir: str) -> str:
    exec_dir = os.path.join(out_dir, "executive")
    os.makedirs(exec_dir, exist_ok=True)
    os.makedirs(os.path.join(exec_dir, "projects"), exist_ok=True)
    os.makedirs(os.path.join(exec_dir, "kubernetes"), exist_ok=True)
    os.makedirs(os.path.join(exec_dir, "assets"), exist_ok=True)
    return exec_dir


def read_csv(path: str) -> List[Dict[str, str]]:
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def write_md(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def md_table(headers: List[str], rows: List[List[str]]) -> str:
    """Generate Markdown table from headers and rows.

    Args:
        headers: Column header names
        rows: 2D list of cell values

    Returns:
        Markdown formatted table string
    """
    return table(headers, rows)


def generate_project_tables(
    out_dir: str, all_projects: Optional[List[str]] = None
) -> Dict[str, Dict[str, str]]:
    exec_dir = ensure_exec_dir(out_dir)
    datasets = {
        "compute": read_csv(os.path.join(out_dir, "csv", "compute.csv")),
        "storage": read_csv(os.path.join(out_dir, "csv", "storage.csv")),
        "networking": read_csv(os.path.join(out_dir, "csv", "networking.csv")),
        "serverless": read_csv(os.path.join(out_dir, "csv", "serverless.csv")),
        "data_analytics": read_csv(os.path.join(out_dir, "csv", "data_analytics.csv")),
        "security": read_csv(os.path.join(out_dir, "csv", "security.csv")),
        "kubernetes": read_csv(os.path.join(out_dir, "csv", "kubernetes.csv")),
    }
    grouped: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
    for name, rows in datasets.items():
        for r in rows:
            pid = r.get("project_id", "unknown")
            grouped.setdefault(pid, {}).setdefault(name, []).append(r)
    index: Dict[str, Dict[str, str]] = {}
    target_projects = set(all_projects or []) | set(grouped.keys())
    for pid in sorted(target_projects):
        cats = grouped.get(pid, {})
        pdir = os.path.join(exec_dir, "projects", pid, "tables")
        os.makedirs(pdir, exist_ok=True)
        index[pid] = {}
        categories = [
            "compute",
            "storage",
            "networking",
            "serverless",
            "data_analytics",
            "security",
            "kubernetes",
        ]
        for cat in categories:
            rows = cats.get(cat, [])
            headers = [
                "project_id",
                "resource_name",
                "type",
                "region",
                "creation_date",
                "last_modified",
                "owner",
                "cost_center",
                "tags",
            ]
            md_rows = [[r.get(h, "") for h in headers] for r in rows]
            content = f"# {pid} · {cat}\n\n" + md_table(headers, md_rows)
            fpath = os.path.join(pdir, f"{cat}.md")
            write_md(fpath, content)
            index[pid][cat] = os.path.relpath(fpath, exec_dir)
    return index


def extract_kubernetes(out_dir: str) -> List[Dict[str, str]]:
    raw_dir = os.path.join(out_dir, "raw")
    clusters: List[Dict[str, str]] = []
    if not os.path.isdir(raw_dir):
        return clusters
    for fn in os.listdir(raw_dir):
        if not fn.endswith("_assets.json"):
            continue
        pid = fn.replace("_assets.json", "")
        with open(os.path.join(raw_dir, fn), "r") as f:
            try:
                assets = json.load(f)
            except json.JSONDecodeError as e:
                log.warning(
                    "docs.json_parse_error", file=fn, error=str(e), security_event=True
                )
                assets = []
        for a in assets:
            if "container.googleapis.com/Cluster" in a.get("assetType", ""):
                data = a.get("resource", {}).get("data", {})
                clusters.append(
                    {
                        "project_id": pid,
                        "name": a.get("name", ""),
                        "location": data.get("location", ""),
                        "masterVersion": data.get("currentMasterVersion", ""),
                        "network": data.get("network", ""),
                        "subnetwork": data.get("subnetwork", ""),
                        "labels": ",".join(
                            [
                                f"{k}:{v}"
                                for k, v in (data.get("labels", {}) or {}).items()
                            ]
                        ),
                    }
                )
    return clusters


def generate_kubernetes_docs(out_dir: str, author: str) -> Dict[str, str]:
    exec_dir = ensure_exec_dir(out_dir)
    clusters = extract_kubernetes(out_dir)
    headers = [
        "project_id",
        "name",
        "location",
        "masterVersion",
        "network",
        "subnetwork",
        "labels",
    ]
    rows = [[c.get(h, "") for h in headers] for c in clusters]
    summary = f"# Kubernetes Catalog\n\nAuthor: {author}\n\n" + md_table(headers, rows)
    summary_path = os.path.join(exec_dir, "kubernetes", "catalog.md")
    write_md(summary_path, summary)
    return {"summary": os.path.relpath(summary_path, exec_dir)}


def generate_kubernetes_csv(out_dir: str) -> str:
    os.makedirs(os.path.join(out_dir, "csv"), exist_ok=True)
    clusters = extract_kubernetes(out_dir)
    if not clusters:
        try:
            from ..gcp.auth import load_credentials
            from ..gcp.client import build_container, list_gke_clusters
            from .settings import load_settings

            s = load_settings(None)
            creds, _ = load_credentials(None)
            container = build_container(creds)
            for pid in s.catalog.projects:
                for c in list_gke_clusters(container, pid):
                    clusters.append(
                        {
                            "project_id": pid,
                            "name": c.get("name", ""),
                            "location": c.get("location", ""),
                            "masterVersion": c.get("currentMasterVersion", ""),
                            "network": c.get("network", ""),
                            "subnetwork": c.get("subnetwork", ""),
                            "labels": ",".join(
                                [
                                    f"{k}:{v}"
                                    for k, v in (
                                        c.get("resourceLabels", {}) or {}
                                    ).items()
                                ]
                            ),
                        }
                    )
        except Exception:
            clusters = []
    path = os.path.join(out_dir, "csv", "kubernetes.csv")
    headers = [
        "project_id",
        "resource_name",
        "type",
        "region",
        "creation_date",
        "last_modified",
        "owner",
        "cost_center",
        "tags",
    ]
    rows: List[List[str]] = []
    rows.append(headers)
    for c in clusters:
        rows.append(
            [
                c.get("project_id", ""),
                c.get("name", ""),
                "gke.cluster",
                c.get("location", ""),
                "",
                "",
                "",
                "",
                c.get("labels", ""),
            ]
        )
    with open(path, "w") as f:
        f.write("\n".join([",".join(r) for r in rows]) + "\n")
    return path


def build_index(
    out_dir: str,
    author: str,
    project_index: Dict[str, Dict[str, str]],
    kube_index: Dict[str, str],
) -> str:
    exec_dir = ensure_exec_dir(out_dir)
    lines: List[str] = []
    lines.append("# Project Documentation Index")
    lines.append("")
    lines.append(f"Author: {author}")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("")
    lines.append("## Table of Contents")
    lines.append(
        f"- [Kubernetes Catalog]({kube_index.get('summary', 'kubernetes/catalog.md')})"
    )
    lines.append("- Summaries:")
    lines.append("  - [Buckets](summaries/buckets.md)")
    lines.append("  - [Cloud SQL](summaries/sql.md)")
    lines.append("  - [Virtual Machines](summaries/vms.md)")
    lines.append("  - [Used Services](assets/used_services.md)")
    lines.append(
        "- [Executive Report](executive/Head-of-Project-Executive-Report.html)"
    )
    lines.append("- Projects:")
    for pid, cats in sorted(project_index.items()):
        lines.append(f"  - {pid}")
        for cat, rel in sorted(cats.items()):
            lines.append(f"    - [{cat}]({rel})")
    index_md = "\n".join(lines) + "\n"
    path = os.path.join(exec_dir, "index.md")
    write_md(path, index_md)
    return path


def generate_asset_summaries(out_dir: str) -> None:
    exec_dir = ensure_exec_dir(out_dir)
    raw_dir = os.path.join(out_dir, "raw")

    def collect(predicate):
        items = []
        if not os.path.isdir(raw_dir):
            return items
        for fn in os.listdir(raw_dir):
            if not fn.endswith("_assets.json"):
                continue
            pid = fn.replace("_assets.json", "")
            with open(os.path.join(raw_dir, fn), "r") as f:
                try:
                    assets = json.load(f)
                except Exception:
                    assets = []
            for a in assets:
                if predicate(a):
                    data = a.get("resource", {}).get("data", {})
                    items.append(
                        [
                            pid,
                            a.get("name", ""),
                            data.get("location", "") or a.get("location", ""),
                            a.get("createTime", ""),
                            ",".join(
                                [
                                    f"{k}:{v}"
                                    for k, v in (data.get("labels", {}) or {}).items()
                                ]
                            ),
                        ]
                    )
        return items

    headers = ["project_id", "name", "location", "created", "labels"]
    buckets = collect(
        lambda a: "storage.googleapis.com/Bucket" in a.get("assetType", "")
    )
    sqls = collect(
        lambda a: "sqladmin.googleapis.com/Instance" in a.get("assetType", "")
    )
    vms = collect(lambda a: "compute.googleapis.com/Instance" in a.get("assetType", ""))
    sums_dir = os.path.join(exec_dir, "summaries")
    os.makedirs(sums_dir, exist_ok=True)
    write_md(
        os.path.join(sums_dir, "buckets.md"),
        "# Buckets\n\n" + md_table(headers, buckets),
    )
    write_md(
        os.path.join(sums_dir, "sql.md"), "# Cloud SQL\n\n" + md_table(headers, sqls)
    )
    write_md(
        os.path.join(sums_dir, "vms.md"),
        "# Virtual Machines\n\n" + md_table(headers, vms),
    )


def generate_used_services_summary(out_dir: str) -> str:
    exec_dir = ensure_exec_dir(out_dir)
    raw_dir = os.path.join(out_dir, "raw")
    service_map = {
        "container.googleapis.com/Cluster": "GKE Clusters",
        "run.googleapis.com/Service": "Cloud Run Services",
        "cloudfunctions.googleapis.com/Function": "Cloud Functions",
        "artifactregistry.googleapis.com/Repository": "Artifact Registry Repos",
        "pubsub.googleapis.com/Topic": "Pub/Sub Topics",
        "bigquery.googleapis.com/Dataset": "BigQuery Datasets",
        "storage.googleapis.com/Bucket": "Buckets",
        "sqladmin.googleapis.com/Instance": "Cloud SQL Instances",
        "compute.googleapis.com/Instance": "VMs",
    }
    counts: Dict[str, Dict[str, int]] = {}
    if os.path.isdir(raw_dir):
        for fn in os.listdir(raw_dir):
            if not fn.endswith("_assets.json"):
                continue
            pid = fn.replace("_assets.json", "")
            with open(os.path.join(raw_dir, fn), "r") as f:
                try:
                    assets = json.load(f)
                except Exception:
                    assets = []
            for a in assets:
                at = a.get("assetType", "")
                name = service_map.get(at)
                if not name:
                    continue
                counts.setdefault(pid, {}).setdefault(name, 0)
                counts[pid][name] += 1
    headers = ["project_id"] + list(service_map.values())
    rows: List[List[str]] = []
    for pid in sorted(counts.keys()):
        row = [pid]
        for svc in service_map.values():
            row.append(str(counts[pid].get(svc, 0)))
        rows.append(row)
    content = "# Used Services Summary\n\n" + md_table(headers, rows)
    path = os.path.join(exec_dir, "assets", "used_services.md")
    write_md(path, content)
    return os.path.relpath(path, exec_dir)


def write_metadata(
    out_dir: str, author: str, version: str, org_id: str, projects: List[str]
) -> None:
    exec_dir = ensure_exec_dir(out_dir)
    meta = {
        "author": author,
        "version": version,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "org_id": org_id,
        "projects": projects,
    }
    with open(os.path.join(exec_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
