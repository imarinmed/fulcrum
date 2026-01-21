"""
Native GCP Client Library - Modern Python API wrappers.

This module provides a modern interface to GCP services using the official
google-cloud-* client libraries. These are the recommended libraries from Google
and offer better type hints, async support, and more Pythonic interfaces.

Usage:
    from src.gcp.native_client import (
        build_compute_client,
        list_instances,
        list_firewalls,
    )
"""

from typing import Dict, List, Optional, Any
from google.auth.credentials import Credentials


# Compute Engine
def build_compute_client(creds: Credentials):
    """Build a native Compute Engine client."""
    from google.cloud import compute_v1

    return compute_v1.InstancesClient(credentials=cred)


def list_instances_native(project_id: str, creds: Credentials) -> List[Dict]:
    """List all compute instances in a project using native client."""
    from google.cloud import compute_v1

    client = compute_v1.InstancesClient(credentials=cred)
    agg_list = compute_v1.AggregatedListInstancesRequest()
    result = client.aggregated_list(project=project_id, request=agg_list)
    items = []
    for scope, instances in result.items():
        if scope != " zones/-":
            for instance in instances.instances:
                items.append(instance.to_dict())
    return items


def list_firewalls_native(project_id: str, creds: Credentials) -> List[Dict]:
    """List all firewall rules in a project using native client."""
    from google.cloud import compute_v1

    client = compute_v1.FirewallClient(credentials=cred)
    result = client.list(project=project_id)
    return [f.to_dict() for f in result.items]


def list_networks_native(project_id: str, creds: Credentials) -> List[Dict]:
    """List all networks in a project using native client."""
    from google.cloud import compute_v1

    client = compute_v1.NetworksClient(credentials=cred)
    result = client.list(project=project_id)
    return [n.to_dict() for n in result.items]


def list_subnetworks_native(
    project_id: str, region: Optional[str], creds: Credentials
) -> List[Dict]:
    """List all subnetworks in a project/region using native client."""
    from google.cloud import compute_v1

    client = compute_v1.SubnetworksClient(credentials=cred)
    if region:
        result = client.list(project=project_id, region=region)
    else:
        agg_list = compute_v1.AggregatedListSubnetworksRequest()
        result = client.aggregated_list(project=project_id, request=agg_list)
    return [s.to_dict() for s in result.items]


# Cloud Resource Manager
def build_crm_client(creds: Credentials):
    """Build a native Cloud Resource Manager client."""
    from google.cloud import resource_manager

    return resource_manager.Client(credentials=cred)


def get_iam_policy_native(project_id: str, creds: Credentials) -> Dict:
    """Get IAM policy for a project using native client."""
    from google.cloud import resource_manager

    client = resource_manager.Client(credentials=cred)
    project = client.fetch_project(project_id)
    return {"bindings": []}  # Simplified for now


# GKE / Kubernetes Engine
def build_container_client(cred):
    """Build a native GKE/Kubernetes Engine client."""
    from google.cloud import container_v1

    return container_v1.ClusterManagerClient(credentials=cred)


def list_gke_clusters_native(
    project_id: str, region: str, creds: Credentials
) -> List[Dict]:
    """List all GKE clusters in a project using native client."""
    from google.cloud import container_v1

    client = container_v1.ClusterManagerClient(credentials=cred)
    parent = f"projects/{project_id}/locations/{region}"
    result = client.list_clusters(parent=parent)
    return [c.to_dict() for c in result.clusters]


# Storage (using google-cloud-storage which is already native)
def build_storage_client(creds: Credentials):
    """Build a native Cloud Storage client."""
    from google.cloud import storage

    return storage.Client(credentials=creds)


def list_buckets_native(project_id: str, creds: Credentials) -> List[Dict]:
    """List all storage buckets in a project using native client."""
    from google.cloud import storage

    client = storage.Client(credentials=creds)
    items = []
    for bucket in client.list_buckets(project=project_id):
        items.append(
            {
                "name": bucket.name,
                "location": bucket.location,
                "storageClass": getattr(bucket, "storage_class", ""),
                "labels": dict(bucket.labels or {}),
            }
        )
    return items


def list_firewalls_native(project_id: str, creds: Credentials) -> List[Dict]:
    """List all firewall rules in a project using native client."""
    from google.cloud import compute_v1

    client = compute_v1.FirewallClient(credentials=cred)
    result = client.list(project=project_id)
    return [f.to_dict() for f in result.items]


def list_networks_native(project_id: str, creds: Credentials) -> List[Dict]:
    """List all networks in a project using native client."""
    from google.cloud import compute_v1

    client = compute_v1.NetworksClient(credentials=cred)
    result = client.list(project=project_id)
    return [n.to_dict() for n in result.items]


def list_subnetworks_native(
    project_id: str, region: Optional[str], creds: Credentials
) -> List[Dict]:
    """List all subnetworks in a project/region using native client."""
    from google.cloud import compute_v1

    client = compute_v1.SubnetworksClient(credentials=cred)
    if region:
        result = client.list(project=project_id, region=region)
    else:
        agg_list = compute_v1.AggregatedListSubnetworksRequest()
        result = client.aggregated_list(project=project_id, request=agg_list)
    return [s.to_dict() for s in result.items]


# Cloud Resource Manager
def build_crm_client(creds: Credentials):
    """Build a native Cloud Resource Manager client."""
    from google.cloud import resource_manager

    return resource_manager.Client(credentials=cred)


def get_iam_policy_native(project_id: str, creds: Credentials) -> Dict:
    """Get IAM policy for a project using native client."""
    from google.cloud import resource_manager

    client = resource_manager.Client(credentials=cred)
    project = client.fetch_project(project_id)
    return {"bindings": []}  # Simplified for now


# Cloud SQL
def build_sqladmin_client(creds: Credentials):
    """Build a native Cloud SQL Admin client."""
    from google.cloud import sql_admin

    return sql_admin.Client(credentials=cred)


def list_sql_instances_native(project_id: str, creds: Credentials) -> List[Dict]:
    """List all Cloud SQL instances in a project using native client."""
    from google.cloud import sql_admin

    client = sql_admin.Client(credentials=cred)
    result = client.instances_list(project=project_id)
    return [i.to_dict() for i in result.items]


# GKE / Kubernetes Engine
def build_container_client(cred):
    """Build a native GKE/Kubernetes Engine client."""
    from google.cloud import container_v1

    return container_v1.ClusterManagerClient(credentials=cred)


def list_gke_clusters_native(
    project_id: str, region: str, creds: Credentials
) -> List[Dict]:
    """List all GKE clusters in a project using native client."""
    from google.cloud import container_v1

    client = container_v1.ClusterManagerClient(credentials=cred)
    parent = f"projects/{project_id}/locations/{region}"
    result = client.list_clusters(parent=parent)
    return [c.to_dict() for c in result.clusters]


# GKE Backup
def build_gkebackup_client(creds: Credentials):
    """Build a native GKE Backup client."""
    from google.cloud import gkebackup_v1

    return gkebackup_v1.BackupClient(credentials=cred)


def list_backup_plans_native(
    project_id: str, location: str, creds: Credentials
) -> List[Dict]:
    """List GKE Backup plans using native client."""
    from google.cloud import gkebackup_v1

    client = gkebackup_v1.BackupClient(credentials=cred)
    parent = f"projects/{project_id}/locations/{location}"
    result = client.list_backup_plans(parent=parent)
    return [p.to_dict() for p in result.backup_plans]


def list_backups_native(parent_plan_full_name: str, creds: Credentials) -> List[Dict]:
    """List backups for a plan using native client."""
    from google.cloud import gkebackup_v1

    client = gkebackup_v1.BackupClient(credentials=cred)
    result = client.list_backups(parent=parent_plan_full_name)
    return [b.to_dict() for b in result.backups]


# Storage (using google-cloud-storage which is already native)
def build_storage_client(creds: Credentials):
    """Build a native Cloud Storage client."""
    from google.cloud import storage

    return storage.Client(credentials=creds)


def list_buckets_native(project_id: str, creds: Credentials) -> List[Dict]:
    """List all storage buckets in a project using native client."""
    from google.cloud import storage

    client = storage.Client(credentials=creds)
    items = []
    for bucket in client.list_buckets(project=project_id):
        items.append(
            {
                "name": bucket.name,
                "location": bucket.location,
                "storageClass": getattr(bucket, "storage_class", ""),
                "labels": dict(bucket.labels or {}),
            }
        )
    return items
