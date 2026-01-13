from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
import structlog
from .settings import load_settings
from ..gcp.auth import load_credentials
from ..gcp.client import (
    build_compute,
    build_crm,
    build_storage_client,
    list_instances,
    list_firewalls,
    list_networks,
    list_subnetworks,
    get_iam_policy,
    list_buckets,
    build_sqladmin,
    list_sql_instances,
    build_container,
    list_gke_clusters,
)

log = structlog.get_logger()

def collect_project(project: str, creds) -> Dict[str, List[Dict]]:
    compute = build_compute(creds)
    crm = build_crm(creds)
    storage_client = build_storage_client(creds)
    sqladmin = build_sqladmin(creds)
    container = build_container(creds)
    data: Dict[str, List[Dict]] = {}
    data["instances"] = list_instances(compute, project)
    data["firewalls"] = list_firewalls(compute, project)
    data["networks"] = list_networks(compute, project)
    data["subnetworks"] = list_subnetworks(compute, project)
    data["iam_policy"] = [get_iam_policy(crm, project)]
    data["buckets"] = list_buckets(storage_client, project)
    data["sql_instances"] = list_sql_instances(sqladmin, project)
    data["gke_clusters"] = list_gke_clusters(container, project)
    return data

def collect_all(sa_key_path: Optional[str] = None, projects: Optional[List[str]] = None) -> Dict[str, Dict]:
    s = load_settings(None)
    target_projects = projects or s.catalog.projects
    creds, _ = load_credentials(sa_key_path)
    results: Dict[str, Dict] = {}
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(collect_project, p, creds): p for p in target_projects}
        for fut in as_completed(futs):
            pid = futs[fut]
            try:
                results[pid] = fut.result()
            except Exception as e:
                log.error("collect.error", project=pid, err=str(e))
                results[pid] = {"error": str(e)}
    return results
