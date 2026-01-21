"""
GKE Cost Client for Kubernetes infrastructure cost analysis.

Provides integration with:
- GKE Cost Allocation via BigQuery billing exports
- Per-namespace, per-workload cost attribution
- Cluster-level cost aggregation

Usage:
    from src.gcp.gke_cost_client import GKECostClient

    client = GKECostClient(billing_project_id="billing-export-project")
    namespace_costs = client.get_namespace_costs(cluster_name="my-cluster")
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

log = structlog.get_logger()


@dataclass
class NamespaceCost:
    """Cost breakdown by Kubernetes namespace."""

    namespace: str
    cluster_name: str
    cluster_location: str
    total_cost: float
    percentage_of_cluster: float


@dataclass
class WorkloadCost:
    """Cost breakdown by Kubernetes workload."""

    workload_name: str
    workload_type: str
    namespace: str
    cluster_name: str
    total_cost: float
    cpu_cost: float
    memory_cost: float
    storage_cost: float


@dataclass
class ClusterCost:
    """Total cost for a GKE cluster."""

    cluster_name: str
    cluster_location: str
    total_cost: float
    node_count: int
    node_pool_count: int
    avg_cost_per_node: float


@dataclass
class PodCost:
    """Cost breakdown by individual pod."""

    pod_name: str
    namespace: str
    cluster_name: str
    total_cost: float
    cpu_cost: float
    memory_cost: float
    cpu_request: float
    memory_request: float


class GKECostClient:
    """
    Client for GKE cost analysis via BigQuery billing exports.

    Requires:
    - GKE Cost Allocation enabled on clusters
    - Cloud Billing export to BigQuery configured

    Data source: gcp_billing_export_resource_v1_* table
    """

    def __init__(
        self,
        billing_project_id: str,
        creds: Optional[Any] = None,
    ):
        """
        Initialize the GKE cost client.

        Args:
            billing_project_id: GCP project ID containing BigQuery billing exports
            creds: Optional google.auth.Credentials. If None, uses ADC.
        """
        self.billing_project_id = billing_project_id
        self._bigquery_client = None
        self._creds = creds

    def _get_bigquery_client(self):
        """Get or create the BigQuery client."""
        if self._bigquery_client is None:
            from google.cloud import bigquery

            if self._creds:
                self._bigquery_client = bigquery.Client(
                    project=self.billing_project_id, credentials=self._creds
                )
            else:
                self._bigquery_client = bigquery.Client(project=self.billing_project_id)
        return self._bigquery_client

    def get_cluster_costs(
        self,
        billing_account_id: str,
        start_date: datetime,
        end_date: datetime,
        project_filter: Optional[List[str]] = None,
    ) -> List[ClusterCost]:
        """
        Get cost breakdown by GKE cluster.

        Args:
            billing_account_id: Billing account ID
            start_date: Start date for the query
            end_date: End date for the query
            project_filter: Optional list of project IDs to filter

        Returns:
            List of ClusterCost objects sorted by total cost
        """
        client = self._get_bigquery_client()
        table_pattern = f"`{self.billing_project_id}.gcp_billing_export_resource_v1_{billing_account_id}*`"

        where_clauses = [
            "resource.labels.service_name = 'Kubernetes Engine'",
            f"usage_start_time >= TIMESTAMP('{start_date.strftime('%Y-%m-%d')}')",
            f"usage_start_time < TIMESTAMP('{end_date.strftime('%Y-%m-%d')}')",
        ]

        if project_filter:
            project_list = ", ".join(f"'{p}'" for p in project_filter)
            where_clauses.append(f"project.id IN ({project_list})")

        where_clause = " AND ".join(where_clauses)

        query = f"""
        SELECT
            resource.labels.cluster_name as cluster_name,
            resource.labels.cluster_location as cluster_location,
            SUM(cost) as total_cost,
            COUNT(DISTINCT resource.labels.node_name) as node_count,
            COUNT(DISTINCT resource.labels.node_pool_name) as node_pool_count
        FROM {table_pattern}
        WHERE {where_clause}
        GROUP BY cluster_name, cluster_location
        ORDER BY total_cost DESC
        """

        try:
            log.info(
                "gke_cost_client.get_cluster_costs",
                billing_account_id=billing_account_id,
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat(),
            )

            query_job = client.query(query)
            results = list(query_job.result())

            cluster_costs = []
            for row in results:
                total_cost = float(row.total_cost) if row.total_cost else 0.0
                node_count = int(row.node_count) if row.node_count else 0
                cluster_costs.append(
                    ClusterCost(
                        cluster_name=row.cluster_name,
                        cluster_location=row.cluster_location,
                        total_cost=total_cost,
                        node_count=node_count,
                        node_pool_count=int(row.node_pool_count)
                        if row.node_pool_count
                        else 0,
                        avg_cost_per_node=(total_cost / node_count)
                        if node_count > 0
                        else 0.0,
                    )
                )

            log.info(
                "gke_cost_client.cluster_costs_complete",
                billing_account_id=billing_account_id,
                cluster_count=len(cluster_costs),
            )

            return cluster_costs
        except Exception as e:
            log.error(
                "gke_cost_client.cluster_costs_error",
                billing_account_id=billing_account_id,
                error=str(e),
            )
            raise

    def get_namespace_costs(
        self,
        billing_account_id: str,
        start_date: datetime,
        end_date: datetime,
        cluster_name: Optional[str] = None,
        project_filter: Optional[List[str]] = None,
    ) -> List[NamespaceCost]:
        """
        Get cost breakdown by Kubernetes namespace.

        Args:
            billing_account_id: Billing account ID
            start_date: Start date for the query
            end_date: End date for the query
            cluster_name: Optional cluster name to filter
            project_filter: Optional list of project IDs to filter

        Returns:
            List of NamespaceCost objects sorted by total cost
        """
        client = self._get_bigquery_client()
        table_pattern = f"`{self.billing_project_id}.gcp_billing_export_resource_v1_{billing_account_id}*`"

        where_clauses = [
            "resource.labels.service_name = 'Kubernetes Engine'",
            f"usage_start_time >= TIMESTAMP('{start_date.strftime('%Y-%m-%d')}')",
            f"usage_start_time < TIMESTAMP('{end_date.strftime('%Y-%m-%d')}')",
        ]

        if cluster_name:
            where_clauses.append(f"resource.labels.cluster_name = '{cluster_name}'")

        if project_filter:
            project_list = ", ".join(f"'{p}'" for p in project_filter)
            where_clauses.append(f"project.id IN ({project_list})")

        where_clause = " AND ".join(where_clauses)

        query = f"""
        SELECT
            resource.labels.cluster_name as cluster_name,
            resource.labels.cluster_location as cluster_location,
            resource.labels.namespace as namespace,
            SUM(cost) as total_cost
        FROM {table_pattern}
        WHERE {where_clause}
          AND resource.labels.namespace IS NOT NULL
        GROUP BY cluster_name, cluster_location, namespace
        ORDER BY total_cost DESC
        """

        try:
            log.info(
                "gke_cost_client.get_namespace_costs",
                billing_account_id=billing_account_id,
                cluster_name=cluster_name,
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat(),
            )

            query_job = client.query(query)
            results = list(query_job.result())

            # Calculate totals for percentage calculation
            total_by_cluster = {}
            for row in results:
                cluster_key = (row.cluster_name, row.cluster_location)
                cost = float(row.total_cost) if row.total_cost else 0.0
                total_by_cluster[cluster_key] = (
                    total_by_cluster.get(cluster_key, 0.0) + cost
                )

            namespace_costs = []
            for row in results:
                total_cost = float(row.total_cost) if row.total_cost else 0.0
                cluster_key = (row.cluster_name, row.cluster_location)
                cluster_total = total_by_cluster.get(cluster_key, 1.0)

                namespace_costs.append(
                    NamespaceCost(
                        namespace=row.namespace,
                        cluster_name=row.cluster_name,
                        cluster_location=row.cluster_location,
                        total_cost=total_cost,
                        percentage_of_cluster=(total_cost / cluster_total * 100)
                        if cluster_total > 0
                        else 0.0,
                    )
                )

            log.info(
                "gke_cost_client.namespace_costs_complete",
                billing_account_id=billing_account_id,
                namespace_count=len(namespace_costs),
            )

            return namespace_costs
        except Exception as e:
            log.error(
                "gke_cost_client.namespace_costs_error",
                billing_account_id=billing_account_id,
                error=str(e),
            )
            raise

    def get_workload_costs(
        self,
        billing_account_id: str,
        start_date: datetime,
        end_date: datetime,
        cluster_name: Optional[str] = None,
        namespace: Optional[str] = None,
        project_filter: Optional[List[str]] = None,
    ) -> List[WorkloadCost]:
        """
        Get cost breakdown by Kubernetes workload.

        Args:
            billing_account_id: Billing account ID
            start_date: Start date for the query
            end_date: End date for the query
            cluster_name: Optional cluster name to filter
            namespace: Optional namespace to filter
            project_filter: Optional list of project IDs to filter

        Returns:
            List of WorkloadCost objects sorted by total cost
        """
        client = self._get_bigquery_client()
        table_pattern = f"`{self.billing_project_id}.gcp_billing_export_resource_v1_{billing_account_id}*`"

        where_clauses = [
            "resource.labels.service_name = 'Kubernetes Engine'",
            f"usage_start_time >= TIMESTAMP('{start_date.strftime('%Y-%m-%d')}')",
            f"usage_start_time < TIMESTAMP('{end_date.strftime('%Y-%m-%d')}')",
        ]

        if cluster_name:
            where_clauses.append(f"resource.labels.cluster_name = '{cluster_name}'")

        if namespace:
            where_clauses.append(f"resource.labels.namespace = '{namespace}'")

        if project_filter:
            project_list = ", ".join(f"'{p}'" for p in project_filter)
            where_clauses.append(f"project.id IN ({project_list})")

        where_clause = " AND ".join(where_clauses)

        query = f"""
        SELECT
            resource.labels.pod_name as pod_name,
            resource.labels.namespace as namespace,
            resource.labels.cluster_name as cluster_name,
            resource.labels.cluster_location as cluster_location,
            resource.labels.workload_name as workload_name,
            resource.labels.workload_kind as workload_kind,
            SUM(cost) as total_cost,
            SUM(IF(resource.labels.topology_kubernetes_io/workload = 'pod', cost, 0)) as pod_cost
        FROM {table_pattern}
        WHERE {where_clause}
        GROUP BY pod_name, namespace, cluster_name, cluster_location, workload_name, workload_kind
        ORDER BY total_cost DESC
        """

        try:
            log.info(
                "gke_cost_client.get_workload_costs",
                billing_account_id=billing_account_id,
                cluster_name=cluster_name,
                namespace=namespace,
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat(),
            )

            query_job = client.query(query)
            results = list(query_job.result())

            workload_costs = []
            for row in results:
                total_cost = float(row.total_cost) if row.total_cost else 0.0
                workload_costs.append(
                    WorkloadCost(
                        workload_name=row.workload_name or row.pod_name,
                        workload_type=row.workload_kind or "Pod",
                        namespace=row.namespace,
                        cluster_name=row.cluster_name,
                        total_cost=total_cost,
                        cpu_cost=0.0,  # Would require separate metric query
                        memory_cost=0.0,  # Would require separate metric query
                        storage_cost=total_cost,  # Simplified - all cost attributed to storage
                    )
                )

            log.info(
                "gke_cost_client.workload_costs_complete",
                billing_account_id=billing_account_id,
                workload_count=len(workload_costs),
            )

            return workload_costs
        except Exception as e:
            log.error(
                "gke_cost_client.workload_costs_error",
                billing_account_id=billing_account_id,
                error=str(e),
            )
            raise

    def get_gke_cost_summary(
        self,
        billing_account_id: str,
        start_date: datetime,
        end_date: datetime,
        project_filter: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Get comprehensive GKE cost summary.

        Args:
            billing_account_id: Billing account ID
            start_date: Start date for the query
            end_date: End date for the query
            project_filter: Optional list of project IDs to filter

        Returns:
            Dictionary with cluster, namespace, and workload cost breakdowns
        """
        try:
            cluster_costs = self.get_cluster_costs(
                billing_account_id=billing_account_id,
                start_date=start_date,
                end_date=end_date,
                project_filter=project_filter,
            )

            namespace_costs = self.get_namespace_costs(
                billing_account_id=billing_account_id,
                start_date=start_date,
                end_date=end_date,
                project_filter=project_filter,
            )

            workload_costs = self.get_workload_costs(
                billing_account_id=billing_account_id,
                start_date=start_date,
                end_date=end_date,
                project_filter=project_filter,
            )

            # Calculate totals
            total_cost = sum(c.total_cost for c in cluster_costs)

            summary = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "billing_account_id": billing_account_id,
                "date_range": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat(),
                },
                "total_cost": total_cost,
                "cluster_count": len(cluster_costs),
                "namespace_count": len(
                    set((nc.namespace, nc.cluster_name) for nc in namespace_costs)
                ),
                "workload_count": len(
                    set((wc.workload_name, wc.namespace) for wc in workload_costs)
                ),
                "clusters": [
                    {
                        "cluster_name": c.cluster_name,
                        "location": c.cluster_location,
                        "total_cost": c.total_cost,
                        "node_count": c.node_count,
                        "avg_cost_per_node": c.avg_cost_per_node,
                    }
                    for c in cluster_costs
                ],
                "namespaces": [
                    {
                        "namespace": nc.namespace,
                        "cluster_name": nc.cluster_name,
                        "total_cost": nc.total_cost,
                        "percentage_of_cluster": nc.percentage_of_cluster,
                    }
                    for nc in namespace_costs
                ],
                "workloads": [
                    {
                        "workload_name": wc.workload_name,
                        "workload_type": wc.workload_type,
                        "namespace": wc.namespace,
                        "cluster_name": wc.cluster_name,
                        "total_cost": wc.total_cost,
                    }
                    for wc in workload_costs[:100]  # Limit to top 100 workloads
                ],
            }

            log.info(
                "gke_cost_client.summary_complete",
                billing_account_id=billing_account_id,
                total_cost=total_cost,
                cluster_count=len(cluster_costs),
            )

            return summary
        except Exception as e:
            log.error(
                "gke_cost_client.summary_error",
                billing_account_id=billing_account_id,
                error=str(e),
            )
            raise
