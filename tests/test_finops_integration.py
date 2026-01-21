from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from fulcrum.cli import app
from fulcrum.commands import finops as finops_cmd
from fulcrum.gcp.finops_client import GCPFinOpsClient
from fulcrum.gcp.gke_cost_client import GKECostClient


class _FakeQueryJob:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return self._rows


class _FakeBigQueryClient:
    def __init__(self, rows):
        self._rows = rows
        self.queries = []

    def query(self, query):
        self.queries.append(query)
        return _FakeQueryJob(self._rows)


class _FakeBillingClient:
    def __init__(self, accounts=None, services=None, skus=None):
        self._accounts = accounts or []
        self._services = services or []
        self._skus = skus or []

    def list_billing_accounts(self):
        return self._accounts

    def list_services(self):
        return self._services

    def list_skus(self, parent):
        return self._skus


class _FakeRecommendation:
    def __init__(self):
        self.name = "projects/p1/locations/global/recommenders/rec/recommendations/abc"
        self.description = "Use smaller machine"
        self.category = "COST"
        self.priority = "P1"
        self.primary_impact = SimpleNamespace(
            cost_projection=SimpleNamespace(cost=SimpleNamespace(units=5, nanos=0))
        )
        self.content = SimpleNamespace(
            impacted_resources=[SimpleNamespace(resource="projects/p1/zones/z1")]
        )
        self.state_info = SimpleNamespace(state="ACTIVE")


class _FakeRecommenderClient:
    def list_recommendations(self, request):
        return [_FakeRecommendation()]


def test_finops_client_lists_accounts_and_services(monkeypatch):
    client = GCPFinOpsClient(billing_project_id="billing-project")
    account = SimpleNamespace(
        name="billingAccounts/123",
        display_name="Main",
        open=True,
        master_billing_account=None,
    )
    service = SimpleNamespace(
        name="services/abc",
        display_name="Compute Engine",
    )
    billing_client = _FakeBillingClient(accounts=[account], services=[service], skus=[])

    monkeypatch.setattr(client, "_get_billing_client", lambda: billing_client)

    accounts = client.list_billing_accounts()
    services = client.list_services()

    assert accounts[0].display_name == "Main"
    assert services[0].display_name == "Compute Engine"


def test_finops_client_recommendations(monkeypatch):
    client = GCPFinOpsClient(billing_project_id="billing-project")

    monkeypatch.setattr(
        client, "_get_recommender_client", lambda: _FakeRecommenderClient()
    )

    recommendations = client.get_recommendations(recommender_id="rec", project_id="p1")

    assert recommendations
    assert recommendations[0].recommender_id == "rec"


def test_finops_client_cost_summary(monkeypatch):
    client = GCPFinOpsClient(billing_project_id="billing-project")

    row = SimpleNamespace(total_cost=12.5, service_id="svc", service_name="Compute")
    bigquery_client = _FakeBigQueryClient([row])

    monkeypatch.setattr(client, "_get_bigquery_client", lambda: bigquery_client)

    cost_by_service = client.get_cost_summary_by_service(
        billing_account_id="billing-account",
        start_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
        end_date=datetime(2025, 1, 2, tzinfo=timezone.utc),
    )

    assert cost_by_service[0].service_display_name == "Compute"


def test_gke_cost_client_summary(monkeypatch):
    client = GKECostClient(billing_project_id="billing-project")
    row = SimpleNamespace(
        total_cost=5.0,
        cluster_name="cluster-1",
        cluster_location="us-central1",
        node_count=2,
        node_pool_count=1,
        namespace="default",
        workload_name="app",
        workload_kind="Deployment",
        pod_name="pod-1",
    )
    bigquery_client = _FakeBigQueryClient([row])

    monkeypatch.setattr(client, "_get_bigquery_client", lambda: bigquery_client)

    summary = client.get_gke_cost_summary(
        billing_account_id="billing-account",
        start_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
        end_date=datetime(2025, 1, 2, tzinfo=timezone.utc),
    )

    assert summary["cluster_count"] == 1
    assert summary["namespace_count"] == 1
    assert summary["workload_count"] == 1


def test_finops_cost_summary_command(monkeypatch, tmp_path):
    def fake_defaults(config_path=None):
        return {
            "org_id": "",
            "billing_project_id": "billing-project",
            "billing_account_id": "billing-account",
            "default_days": 30,
            "include_recommendations": True,
            "include_gke_costs": True,
            "recommenders": ["rec"],
            "config_path": config_path,
        }

    fake_settings = SimpleNamespace(
        catalog=SimpleNamespace(projects=["p1"]),
        finops=SimpleNamespace(
            billing_project_id="billing-project",
            billing_account_id="billing-account",
            default_date_range_days=30,
            include_recommendations=True,
            include_gke_costs=True,
            recommenders=["rec"],
        ),
    )

    monkeypatch.setattr(finops_cmd, "_get_finops_defaults", fake_defaults)
    monkeypatch.setattr(finops_cmd, "load_settings", lambda _: fake_settings)
    monkeypatch.setattr(
        finops_cmd,
        "GCPFinOpsClient",
        lambda billing_project_id: SimpleNamespace(
            get_cost_summary_by_service=lambda **kwargs: [
                SimpleNamespace(
                    service_display_name="Compute",
                    total_cost=12.5,
                    percentage_of_total=100.0,
                )
            ],
            get_cost_summary_by_project=lambda **kwargs: [
                SimpleNamespace(
                    project_id="p1",
                    project_name="Project 1",
                    total_cost=12.5,
                    percentage_of_total=100.0,
                )
            ],
        ),
    )
    monkeypatch.setattr(
        finops_cmd,
        "GKECostClient",
        lambda billing_project_id: SimpleNamespace(
            get_gke_cost_summary=lambda **kwargs: {
                "clusters": [
                    {
                        "cluster_name": "cluster-1",
                        "location": "us-central1",
                        "total_cost": 1.0,
                        "node_count": 1,
                    }
                ],
                "cluster_count": 1,
            }
        ),
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "finops",
            "cost-summary",
            "--billing-project",
            "billing-project",
            "--billing-account",
            "billing-account",
            "--output",
            str(tmp_path),
            "--project",
            "p1",
            "--days",
            "1",
        ],
    )

    assert result.exit_code == 0


def test_finops_gke_costs_command(monkeypatch, tmp_path):
    def fake_defaults(config_path=None):
        return {
            "org_id": "",
            "billing_project_id": "billing-project",
            "billing_account_id": "billing-account",
            "default_days": 30,
            "include_recommendations": True,
            "include_gke_costs": True,
            "recommenders": ["rec"],
            "config_path": config_path,
        }

    fake_settings = SimpleNamespace(
        catalog=SimpleNamespace(projects=["p1"]),
        finops=SimpleNamespace(
            billing_project_id="billing-project",
            billing_account_id="billing-account",
            default_date_range_days=30,
            include_recommendations=True,
            include_gke_costs=True,
            recommenders=["rec"],
        ),
    )

    monkeypatch.setattr(finops_cmd, "_get_finops_defaults", fake_defaults)
    monkeypatch.setattr(finops_cmd, "load_settings", lambda _: fake_settings)
    monkeypatch.setattr(
        finops_cmd,
        "GKECostClient",
        lambda billing_project_id: SimpleNamespace(
            get_gke_cost_summary=lambda **kwargs: {
                "clusters": [
                    {
                        "cluster_name": "cluster-1",
                        "location": "us-central1",
                        "total_cost": 1.0,
                        "node_count": 1,
                        "avg_cost_per_node": 1.0,
                    }
                ],
                "namespaces": [
                    {
                        "namespace": "default",
                        "cluster_name": "cluster-1",
                        "total_cost": 1.0,
                        "percentage_of_cluster": 100.0,
                    }
                ],
                "workloads": [
                    {
                        "workload_name": "app",
                        "workload_type": "Deployment",
                        "namespace": "default",
                        "cluster_name": "cluster-1",
                        "total_cost": 1.0,
                    }
                ],
                "total_cost": 1.0,
                "cluster_count": 1,
                "namespace_count": 1,
                "workload_count": 1,
            }
        ),
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "finops",
            "gke-costs",
            "--billing-project",
            "billing-project",
            "--billing-account",
            "billing-account",
            "--output",
            str(tmp_path),
            "--project",
            "p1",
            "--days",
            "1",
        ],
    )

    assert result.exit_code == 0
