"""
GCP FinOps Client for cost management and optimization.

Provides integration with:
- Cloud Billing API for billing account and SKU information
- Recommender API for cost optimization recommendations
- BigQuery billing exports for detailed cost analysis
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

log = structlog.get_logger()


@dataclass
class GCPServiceInfo:
    """Information about a GCP service."""

    service_id: str
    display_name: str
    service_name: str


@dataclass
class GCPBillingAccount:
    """Information about a billing account."""

    name: str
    display_name: str
    open: bool
    master_billing_account: Optional[str] = None


@dataclass
class CostRecommendation:
    """Cost optimization recommendation."""

    recommender_id: str
    recommendation_id: str
    description: str
    category: str
    priority: str
    projected_monthly_savings: float
    current_spend: float
    affected_resources: List[str]
    state: str
    last_refresh: datetime


@dataclass
class CostByService:
    """Cost breakdown by GCP service."""

    service_name: str
    service_display_name: str
    total_cost: float
    percentage_of_total: float


@dataclass
class CostByProject:
    """Cost breakdown by GCP project."""

    project_id: str
    project_name: str
    total_cost: float
    percentage_of_total: float


class GCPFinOpsClient:
    """Unified client for GCP FinOps operations."""

    def __init__(self, billing_project_id: str, quota_project: Optional[str] = None):
        """
        Initialize the FinOps client.

        Args:
            billing_project_id: GCP project ID containing BigQuery billing exports
            quota_project: Optional quota project for Recommender API (required for some APIs)
        """
        self.billing_project_id = billing_project_id
        self._billing_client = None
        self._recommender_client = None
        self._bigquery_client = None
        self._quota_project = quota_project or billing_project_id

        # Set quota project via environment variable if provided
        if quota_project:
            import os

            os.environ["GOOGLE_CLOUD_QUOTA_PROJECT"] = quota_project

    def _get_billing_client(self) -> Any:
        """Get or create the Cloud Billing API client."""
        if self._billing_client is None:
            from google.cloud import billing_v1

            self._billing_client = billing_v1.CloudBillingClient()
        return self._billing_client

    def _get_recommender_client(self) -> Any:
        """Get or create the Recommender API client."""
        if self._recommender_client is None:
            from google.cloud import recommender_v1

            self._recommender_client = recommender_v1.RecommenderClient()
        return self._recommender_client

    def _get_bigquery_client(self) -> Any:
        """Get or create the BigQuery client."""
        if self._bigquery_client is None:
            from google.cloud import bigquery

            self._bigquery_client = bigquery.Client(project=self.billing_project_id)
        return self._bigquery_client

    def list_billing_accounts(self) -> List[GCPBillingAccount]:
        """List all billing accounts accessible by the credentials."""
        client = self._get_billing_client()
        accounts = []

        try:
            for account in client.list_billing_accounts():
                accounts.append(
                    GCPBillingAccount(
                        name=account.name,
                        display_name=account.display_name,
                        open=account.open,
                        master_billing_account=getattr(
                            account, "master_billing_account", None
                        ),
                    )
                )
            log.info("finops_client.billing_accounts_retrieved", count=len(accounts))
        except Exception as e:
            log.error("finops_client.billing_accounts_error", error=str(e))
            raise

        return accounts

    def list_services(self) -> List[GCPServiceInfo]:
        """List all available GCP services with their SKUs and pricing."""
        client = self._get_billing_client()
        services = []

        try:
            for service in client.list_services():
                services.append(
                    GCPServiceInfo(
                        service_id=service.name.split("/")[-1],
                        display_name=service.display_name,
                        service_name=service.name,
                    )
                )
            log.info("finops_client.services_retrieved", count=len(services))
        except Exception as e:
            log.error("finops_client.services_error", error=str(e))
            raise

        return services

    def get_sku_pricing(self, service_id: str) -> List[Dict[str, Any]]:
        """Get pricing information for all SKUs in a service."""
        client = self._get_billing_client()
        service_name = f"services/{service_id}"
        skus = []

        try:
            for sku in client.list_skus(parent=service_name):
                sku_info = {
                    "sku_id": sku.sku_id,
                    "sku_name": sku.name,
                    "display_name": sku.display_name,
                    "category": {
                        "service_family": sku.category.service_family,
                        "resource_family": sku.category.resource_family,
                        "resource_group": sku.category.resource_group,
                    },
                    "pricing_info": [],
                }

                for pricing_unit in sku.pricing_info:
                    pricing_info = {
                        "unit": pricing_unit.unit,
                        "unit_count": pricing_unit.unit_count,
                        "aggregate_quantity": pricing_unit.aggregate_quantity,
                        "effective_unit_price": None,
                    }

                    if pricing_unit.exclusive_price:
                        pricing_info["effective_unit_price"] = {
                            "currency_code": pricing_unit.exclusive_price.currency_code,
                            "units": pricing_unit.exclusive_price.units,
                            "nanos": pricing_unit.exclusive_price.nanos,
                        }

                    sku_info["pricing_info"].append(pricing_info)

                skus.append(sku_info)

            log.info(
                "finops_client.skus_retrieved", service_id=service_id, count=len(skus)
            )
        except Exception as e:
            log.error("finops_client.skus_error", service_id=service_id, error=str(e))
            raise

        return skus

    def get_recommendations(
        self,
        recommender_id: str,
        project_id: Optional[str] = None,
        location: str = "global",
    ) -> List[CostRecommendation]:
        """Get cost optimization recommendations for a specific recommender."""
        client = self._get_recommender_client()
        recommendations = []

        try:
            if project_id:
                parent = f"projects/{project_id}/locations/{location}/recommenders/{recommender_id}"
            else:
                parent = (
                    f"projects/-/locations/{location}/recommenders/{recommender_id}"
                )

            from google.cloud import recommender_v1

            request = recommender_v1.ListRecommendationsRequest(parent=parent)

            for rec in client.list_recommendations(request=request):
                cost_impact = 0.0
                current_spend = 0.0

                if rec.primary_impact and rec.primary_impact.cost_projection:
                    cost_projection = rec.primary_impact.cost_projection
                    if cost_projection.cost:
                        cost_impact = float(cost_projection.cost.units) + (
                            cost_projection.cost.nanos / 1e9
                        )

                affected_resources = []
                for resource in rec.content.impacted_resources:
                    affected_resources.append(resource.resource)

                recommendations.append(
                    CostRecommendation(
                        recommender_id=recommender_id,
                        recommendation_id=rec.name.split("/")[-1],
                        description=rec.description,
                        category=rec.category,
                        priority=rec.priority,
                        projected_monthly_savings=cost_impact,
                        current_spend=current_spend,
                        affected_resources=affected_resources,
                        state=str(rec.state_info.state),
                        last_refresh=datetime.now(timezone.utc),
                    )
                )

            log.info(
                "finops_client.recommendations_retrieved",
                recommender_id=recommender_id,
                project_id=project_id,
                count=len(recommendations),
            )
        except Exception as e:
            log.error(
                "finops_client.recommendations_error",
                recommender_id=recommender_id,
                project_id=project_id,
                error=str(e),
            )
            raise

        return recommendations

    def query_billing_export(
        self,
        billing_account_id: str,
        start_date: datetime,
        end_date: datetime,
        project_filter: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Query BigQuery billing export for cost data."""
        client = self._get_bigquery_client()
        table_pattern = (
            f"`{self.billing_project_id}.gcp_billing_export_v1.gcp_billing_export_*`"
        )

        where_clauses = [
            f"usage_start_time >= TIMESTAMP('{start_date.strftime('%Y-%m-%d')}')",
            f"usage_start_time < TIMESTAMP('{end_date.strftime('%Y-%m-%d')}')",
        ]

        if project_filter:
            project_list = ", ".join(f"'{p}'" for p in project_filter)
            where_clauses.append(f"project.id IN ({project_list})")

        where_clause = " AND ".join(where_clauses)

        query = f"""
        SELECT
            DATE(usage_start_time) as usage_date,
            project.id as project_id,
            project.name as project_name,
            project.number as project_number,
            service.description as service_name,
            sku.description as sku_name,
            sku.id as sku_id,
            SUM(cost) as total_cost,
            SUM(cost + ifnull((SELECT SUM(amount) FROM UNNEST(credits)), 0)) as total_cost_with_credits,
            SUM(usage.amount_in_pricing_units) as usage_amount,
            usage.pricing_unit as pricing_unit,
            labels,
            resource.name as resource_name,
            resource.type as resource_type,
            location.location as location,
            location.country as country,
            location.region as region
        FROM {table_pattern}
        WHERE {where_clause}
        GROUP BY
            usage_date,
            project_id,
            project_name,
            project_number,
            service_name,
            sku_name,
            sku_id,
            labels,
            resource_name,
            resource_type,
            location,
            country,
            region
        ORDER BY
            usage_date DESC,
            total_cost DESC
        """

        try:
            log.info(
                "finops_client.query_billing_export",
                billing_account_id=billing_account_id,
                start_date=start_date.isoformat(),
                end_date=end_date.isoformat(),
            )

            query_job = client.query(query)
            results = query_job.result()

            costs = []
            for row in results:
                costs.append(
                    {
                        "usage_date": str(row.usage_date),
                        "project_id": row.project_id,
                        "project_name": row.project_name,
                        "project_number": str(row.project_number),
                        "service_name": row.service_name,
                        "sku_name": row.sku_name,
                        "sku_id": row.sku_id,
                        "total_cost": float(row.total_cost) if row.total_cost else 0.0,
                        "total_cost_with_credits": float(row.total_cost_with_credits)
                        if row.total_cost_with_credits
                        else 0.0,
                        "usage_amount": float(row.usage_amount)
                        if row.usage_amount
                        else 0.0,
                        "pricing_unit": row.pricing_unit,
                        "labels": dict(row.labels) if row.labels else {},
                        "resource_name": row.resource_name,
                        "resource_type": row.resource_type,
                        "location": row.location,
                        "country": row.country,
                        "region": row.region,
                    }
                )

            log.info(
                "finops_client.billing_export_query_complete",
                billing_account_id=billing_account_id,
                result_count=len(costs),
            )

            return costs
        except Exception as e:
            log.error(
                "finops_client.billing_export_query_error",
                billing_account_id=billing_account_id,
                error=str(e),
            )
            raise

    def get_cost_summary_by_service(
        self,
        billing_account_id: str,
        start_date: datetime,
        end_date: datetime,
        project_filter: Optional[List[str]] = None,
    ) -> List[CostByService]:
        """Get cost breakdown by GCP service."""
        client = self._get_bigquery_client()
        table_pattern = (
            f"`{self.billing_project_id}.gcp_billing_export_v1.gcp_billing_export_*`"
        )

        where_clauses = [
            f"usage_start_time >= TIMESTAMP('{start_date.strftime('%Y-%m-%d')}')",
            f"usage_start_time < TIMESTAMP('{end_date.strftime('%Y-%m-%d')}')",
        ]

        if project_filter:
            project_list = ", ".join(f"'{p}'" for p in project_filter)
            where_clauses.append(f"project.id IN ({project_list})")

        where_clause = " AND ".join(where_clauses)

        query = f"""
        SELECT
            service.description as service_name,
            service.id as service_id,
            SUM(cost) as total_cost
        FROM {table_pattern}
        WHERE {where_clause}
        GROUP BY service_name, service_id
        ORDER BY total_cost DESC
        """

        try:
            query_job = client.query(query)
            results = list(query_job.result())

            total_cost = sum(
                float(row.total_cost) if row.total_cost else 0.0 for row in results
            )

            cost_by_service = []
            for row in results:
                service_cost = float(row.total_cost) if row.total_cost else 0.0
                cost_by_service.append(
                    CostByService(
                        service_name=row.service_id,
                        service_display_name=row.service_name,
                        total_cost=service_cost,
                        percentage_of_total=(service_cost / total_cost * 100)
                        if total_cost > 0
                        else 0.0,
                    )
                )

            log.info(
                "finops_client.cost_by_service",
                billing_account_id=billing_account_id,
                service_count=len(cost_by_service),
            )

            return cost_by_service
        except Exception as e:
            log.error(
                "finops_client.cost_by_service_error",
                billing_account_id=billing_account_id,
                error=str(e),
            )
            raise

    def get_cost_summary_by_project(
        self,
        billing_account_id: str,
        start_date: datetime,
        end_date: datetime,
        project_filter: Optional[List[str]] = None,
    ) -> List[CostByProject]:
        """Get cost breakdown by GCP project."""
        client = self._get_bigquery_client()
        table_pattern = (
            f"`{self.billing_project_id}.gcp_billing_export_v1.gcp_billing_export_*`"
        )

        where_clauses = [
            f"usage_start_time >= TIMESTAMP('{start_date.strftime('%Y-%m-%d')}')",
            f"usage_start_time < TIMESTAMP('{end_date.strftime('%Y-%m-%d')}')",
        ]

        if project_filter:
            project_list = ", ".join(f"'{p}'" for p in project_filter)
            where_clauses.append(f"project.id IN ({project_list})")

        where_clause = " AND ".join(where_clauses)

        query = f"""
        SELECT
            project.id as project_id,
            project.name as project_name,
            SUM(cost) as total_cost
        FROM {table_pattern}
        WHERE {where_clause}
        GROUP BY project_id, project_name
        ORDER BY total_cost DESC
        """

        try:
            query_job = client.query(query)
            results = list(query_job.result())

            total_cost = sum(
                float(row.total_cost) if row.total_cost else 0.0 for row in results
            )

            cost_by_project = []
            for row in results:
                project_cost = float(row.total_cost) if row.total_cost else 0.0
                cost_by_project.append(
                    CostByProject(
                        project_id=row.project_id,
                        project_name=row.project_name,
                        total_cost=project_cost,
                        percentage_of_total=(project_cost / total_cost * 100)
                        if total_cost > 0
                        else 0.0,
                    )
                )

            log.info(
                "finops_client.cost_by_project",
                billing_account_id=billing_account_id,
                project_count=len(cost_by_project),
            )

            return cost_by_project
        except Exception as e:
            log.error(
                "finops_client.cost_by_project_error",
                billing_account_id=billing_account_id,
                error=str(e),
            )
            raise
