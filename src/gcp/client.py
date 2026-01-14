from typing import Dict, List, Optional


def build_compute(creds):
    from googleapiclient.discovery import build

    return build("compute", "v1", credentials=creds, cache_discovery=False)


def build_crm(creds):
    from googleapiclient.discovery import build

    return build("cloudresourcemanager", "v1", credentials=creds, cache_discovery=False)


def build_storage_client(creds):
    from google.cloud import storage

    return storage.Client(credentials=creds)


def build_sqladmin(creds):
    from googleapiclient.discovery import build

    return build("sqladmin", "v1", credentials=creds, cache_discovery=False)


def list_instances(compute, project: str) -> List[Dict]:
    items: List[Dict] = []
    req = compute.instances().aggregatedList(project=project)
    while req is not None:
        resp = req.execute(num_retries=2)
        for _, zone_data in (resp.get("items") or {}).items():
            for inst in zone_data.get("instances", []):
                items.append(inst)
        req = compute.instances().aggregatedList_next(
            previous_request=req, previous_response=resp
        )
    return items


def list_firewalls(compute, project: str) -> List[Dict]:
    items: List[Dict] = []
    req = compute.firewalls().list(project=project)
    while req is not None:
        resp = req.execute(num_retries=2)
        items.extend(resp.get("items", []))
        req = compute.firewalls().list_next(
            previous_request=req, previous_response=resp
        )
    return items


def list_networks(compute, project: str) -> List[Dict]:
    items: List[Dict] = []
    req = compute.networks().list(project=project)
    while req is not None:
        resp = req.execute(num_retries=2)
        items.extend(resp.get("items", []))
        req = compute.networks().list_next(previous_request=req, previous_response=resp)
    return items


def list_subnetworks(compute, project: str, region: Optional[str] = None) -> List[Dict]:
    items: List[Dict] = []
    if region:
        req = compute.subnetworks().list(project=project, region=region)
        while req is not None:
            resp = req.execute(num_retries=2)
            items.extend(resp.get("items", []))
            req = compute.subnetworks().list_next(
                previous_request=req, previous_response=resp
            )
        return items
    # aggregated across regions
    req = compute.subnetworks().aggregatedList(project=project)
    while req is not None:
        resp = req.execute(num_retries=2)
        for _, reg in (resp.get("items") or {}).items():
            items.extend(reg.get("subnetworks", []))
        req = compute.subnetworks().aggregatedList_next(
            previous_request=req, previous_response=resp
        )
    return items


def get_iam_policy(crm, project: str) -> Dict:
    req = crm.projects().getIamPolicy(resource=project, body={})
    return req.execute(num_retries=2)


def list_buckets(storage_client, project: str) -> List[Dict]:
    items: List[Dict] = []
    for b in storage_client.list_buckets(project=project):
        items.append(
            {
                "name": b.name,
                "location": b.location,
                "storageClass": getattr(b, "storage_class", ""),
                "labels": dict(b.labels or {}),
            }
        )
    return items


def list_sql_instances(sqladmin, project: str) -> List[Dict]:
    items: List[Dict] = []
    req = sqladmin.instances().list(project=project)
    while req is not None:
        resp = req.execute(num_retries=2)
        items.extend(resp.get("items", []))
        req = sqladmin.instances().list_next(
            previous_request=req, previous_response=resp
        )
    return items


def build_container(creds):
    from googleapiclient.discovery import build

    return build("container", "v1", credentials=creds, cache_discovery=False)


def build_gkebackup(creds):
    from googleapiclient.discovery import build

    return build("gkebackup", "v1", credentials=creds, cache_discovery=False)


def list_gke_clusters(container, project: str) -> List[Dict]:
    items: List[Dict] = []
    parent = f"projects/{project}/locations/-"
    req = container.projects().locations().clusters().list(parent=parent)
    resp = req.execute(num_retries=2) or {}
    for c in resp.get("clusters", []):
        items.append(c)
    return items
