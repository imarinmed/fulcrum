"""
FinOps commands for cost management and optimization reports.
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import structlog
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..core.settings import get_cli_defaults, load_settings
from ..gcp.finops_client import GCPFinOpsClient
from ..gcp.gke_cost_client import GKECostClient

log = structlog.get_logger()

console = Console()

finops_app = typer.Typer(
    help="FinOps commands for cost management and optimization reports",
    no_args_is_help=True,
)


def _get_finops_defaults(config_path: Optional[str] = None) -> dict:
    """Get FinOps defaults from config with fallback values."""
    try:
        settings = load_settings(config_path)
        defaults = get_cli_defaults(settings, config_path)
        finops = settings.finops

        return {
            "org_id": defaults.get("org_id", ""),
            "billing_project_id": finops.billing_project_id,
            "billing_account_id": finops.billing_account_id,
            "default_days": finops.default_date_range_days,
            "include_recommendations": finops.include_recommendations,
            "include_gke_costs": finops.include_gke_costs,
            "recommenders": finops.recommenders,
            "config_path": config_path,
        }
    except Exception as e:
        log.warning("finops.cli_defaults_error", error=str(e), security_event=True)
        return {
            "org_id": "",
            "billing_project_id": "",
            "billing_account_id": "",
            "default_days": 30,
            "include_recommendations": True,
            "include_gke_costs": True,
            "recommenders": [
                "google.compute.instance.MachineTypeRecommender",
                "google.cloudsql.instance.IdleRecommender",
                "google.cloudsql.instance.OverprovisionedRecommender",
            ],
            "config_path": config_path,
        }


@finops_app.command("cost-summary")
def cost_summary_cmd(
    all_projects: bool = typer.Option(
        True, "--all/--no-all", help="Analyze all configured projects (default: true)"
    ),
    project: Optional[str] = typer.Option(
        None, "--project", "-p", help="Specific project ID to analyze"
    ),
    org_id: Optional[str] = typer.Option(
        None, "--org-id", "-o", help="Organization ID (uses config if not specified)"
    ),
    billing_project_id: Optional[str] = typer.Option(
        None,
        "--billing-project",
        "-b",
        help="GCP project with BigQuery billing exports (uses config if not specified)",
    ),
    billing_account_id: Optional[str] = typer.Option(
        None,
        "--billing-account",
        "-a",
        help="Billing account ID (uses config if not specified)",
    ),
    days: int = typer.Option(30, "--days", "-d", help="Number of days to analyze"),
    out_dir: str = typer.Option("finops-report", "--output", help="Output directory"),
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to configuration file"
    ),
):
    """
    Generate a cost summary report for GCP projects.

    Can analyze a single project or ALL configured projects.
    Default behavior is to analyze ALL configured projects.

    Configuration values from fulcrum.toml are used as defaults.
    """
    setup_logging()

    # Load config
    settings = load_settings(config)
    defaults = _get_finops_defaults(config)

    # Determine target projects
    target_projects = []
    if project:
        target_projects = [project]
    elif all_projects:
        target_projects = settings.catalog.projects
        if not target_projects:
            console.print(
                "[yellow]Warning: No projects found in configuration. Use --project to specify one.[/]"
            )
    else:
        console.print(
            "[red]Error: Must specify --project or use --all to analyze all configured projects[/]"
        )
        raise typer.Exit(1)

    # Use CLI args or fall back to config defaults
    final_org_id = org_id or defaults["org_id"]
    final_billing_project = billing_project_id or defaults["billing_project_id"]
    final_billing_account = billing_account_id or defaults["billing_account_id"]

    # Validate required parameters
    if not final_billing_project:
        console.print(
            "[red]Error: Billing project ID required for cost analysis.[/]\n\n"
            "This is the GCP project where your Cloud Billing export to BigQuery is configured.\n"
            "Without it, there's no cost data to analyze.\n\n"
            "Setup instructions:\n"
            "  1. Go to Cloud Console > Billing > BigQuery exports\n"
            "  2. Enable billing export to BigQuery in your billing account\n"
            "  3. Note the project ID where exports are stored\n"
            "  4. Set it via: fulcrum finops cost-summary --billing-project PROJECT_ID\n"
            "  5. Or configure in fulcrum.toml: [finops] billing_project_id = 'PROJECT_ID'"
        )
        raise typer.Exit(1)
    if not final_billing_account:
        console.print(
            "[red]Error: Billing account ID required.[/]\n\n"
            "This is your Cloud Billing account ID (format: 123456-789012-3456789).\n"
            "Find it in: Cloud Console > Billing > Account Management\n\n"
            "Set it via: fulcrum finops cost-summary --billing-account ACCOUNT_ID\n"
            "Or configure in fulcrum.toml: [finops] billing_account_id = 'ACCOUNT_ID'"
        )
        raise typer.Exit(1)

    try:
        log.info(
            "finops.cost_summary_start",
            org_id=final_org_id,
            billing_project_id=final_billing_project,
            billing_account_id=final_billing_account,
            days=days,
            target_projects=target_projects,
            all_projects=all_projects,
        )

        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        # Initialize clients
        finops_client = GCPFinOpsClient(billing_project_id=final_billing_project)
        gke_client = GKECostClient(billing_project_id=final_billing_project)

        # Get cost data for all projects
        console.print(
            Panel(
                f"Gathering cost data for {len(target_projects)} project(s)...",
                expand=False,
            )
        )

        cost_by_service = finops_client.get_cost_summary_by_service(
            billing_account_id=final_billing_account,
            start_date=start_date,
            end_date=end_date,
            project_filter=target_projects if target_projects else None,
        )

        cost_by_project = finops_client.get_cost_summary_by_project(
            billing_account_id=final_billing_account,
            start_date=start_date,
            end_date=end_date,
            project_filter=target_projects if target_projects else None,
        )

        # Display cost by service
        console.print(Panel("Cost by GCP Service", expand=False))
        service_table = Table(title="Cost Breakdown by Service")
        service_table.add_column("Service", style="cyan")
        service_table.add_column("Total Cost ($)", justify="right", style="green")
        service_table.add_column("% of Total", justify="right", style="yellow")

        for service in cost_by_service[:10]:  # Top 10
            service_table.add_row(
                service.service_display_name,
                f"${service.total_cost:,.2f}",
                f"{service.percentage_of_total:.1f}%",
            )

        console.print(service_table)
        console.print()

        # Display cost by project
        console.print(Panel("Cost by Project", expand=False))
        project_table = Table(title="Cost Breakdown by Project")
        project_table.add_column("Project ID", style="cyan")
        project_table.add_column("Project Name", style="blue")
        project_table.add_column("Total Cost ($)", justify="right", style="green")
        project_table.add_column("% of Total", justify="right", style="yellow")

        for project in cost_by_project[:10]:  # Top 10
            project_table.add_row(
                project.project_id,
                project.project_name or "N/A",
                f"${project.total_cost:,.2f}",
                f"{project.percentage_of_total:.1f}%",
            )

        console.print(project_table)
        console.print()

        # Get GKE costs if requested
        console.print(Panel("GKE Cost Analysis", expand=False))
        gke_summary = gke_client.get_gke_cost_summary(
            billing_account_id=final_billing_account,
            start_date=start_date,
            end_date=end_date,
        )

        gke_table = Table(title="GKE Cluster Costs")
        gke_table.add_column("Cluster", style="cyan")
        gke_table.add_column("Location", style="blue")
        gke_table.add_column("Total Cost ($)", justify="right", style="green")
        gke_table.add_column("Nodes", justify="right", style="yellow")

        for cluster in gke_summary.get("clusters", []):
            gke_table.add_row(
                cluster["cluster_name"],
                cluster["location"],
                f"${cluster['total_cost']:,.2f}",
                str(cluster["node_count"]),
            )

        console.print(gke_table)
        console.print()

        log.info(
            "finops.cost_summary_complete",
            total_services=len(cost_by_service),
            total_projects=len(cost_by_project),
            total_gke_clusters=gke_summary.get("cluster_count", 0),
        )

        console.print(
            f"[green]✓ Cost summary generated successfully[/]\n"
            f"Report directory: [cyan]{out_dir}[/]"
        )

    except Exception as e:
        log.error("finops.cost_summary_error", error=str(e))
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@finops_app.command("recommendations")
def recommendations_cmd(
    all_projects: bool = typer.Option(
        True, "--all/--no-all", help="Analyze all configured projects (default: true)"
    ),
    project: Optional[str] = typer.Option(
        None, "--project", "-p", help="Specific project ID to analyze"
    ),
    org_id: Optional[str] = typer.Option(
        None, "--org-id", "-o", help="Organization ID (uses config if not specified)"
    ),
    recommenders: Optional[str] = typer.Option(
        None,
        "--recommenders",
        "-r",
        help="Comma-separated list of recommender IDs (uses config if not specified)",
    ),
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to configuration file"
    ),
):
    """
    Generate cost optimization recommendations for GCP projects.

    Can analyze a single project or ALL configured projects.
    Default behavior is to analyze ALL configured projects.

    Configuration values from fulcrum.toml are used as defaults.
    """
    setup_logging()

    # Load config
    settings = load_settings(config)
    defaults = _get_finops_defaults(config)

    # Determine target projects
    target_projects = []
    if project:
        target_projects = [project]
    elif all_projects:
        target_projects = settings.catalog.projects
        if not target_projects:
            console.print(
                "[yellow]Warning: No projects found in configuration. Use --project to specify one.[/]"
            )
    else:
        console.print(
            "[red]Error: Must specify --project or use --all to analyze all configured projects[/]"
        )
        raise typer.Exit(1)

    # Use CLI args or fall back to config defaults
    final_org_id = org_id or defaults["org_id"]
    final_recommenders = (
        recommenders.split(",") if recommenders else defaults["recommenders"]
    )

    try:
        log.info(
            "finops.recommendations_start",
            org_id=final_org_id,
            target_projects=target_projects,
            recommenders=final_recommenders,
            all_projects=all_projects,
        )

        console.print(
            Panel(
                f"Gathering recommendations for {len(target_projects)} project(s)...",
                expand=False,
            )
        )

        all_recommendations = []
        processed_projects = set()

        # Query each project individually to avoid cross-project API issues
        for target_project in target_projects:
            if target_project in processed_projects:
                continue
            processed_projects.add(target_project)

            console.print(f"\n[cyan]Checking project: {target_project}[/]")

            for recommender_id in final_recommenders:
                try:
                    finops_client = GCPFinOpsClient(
                        billing_project_id="", quota_project=target_project
                    )

                    recommendations = finops_client.get_recommendations(
                        recommender_id=recommender_id,
                        project_id=target_project,
                    )

                    if recommendations:
                        all_recommendations.extend(recommendations)
                        console.print(
                            f"  ✓ Found {len(recommendations)} recommendations from {recommender_id.split('.')[-1]}"
                        )
                    else:
                        console.print(
                            f"  → {recommender_id.split('.')[-1]}: No recommendations"
                        )

                except Exception as rec_error:
                    error_msg = str(rec_error)
                    if "500" in error_msg or "Internal" in error_msg:
                        console.print(
                            f"  [yellow]⚠ {recommender_id.split('.')[-1]}: API error (will retry later)[/]"
                        )
                        log.warning(
                            "finops.recommender_api_error",
                            recommender_id=recommender_id,
                            project=target_project,
                            error=error_msg,
                        )
                    elif (
                        "permission" in error_msg.lower()
                        or "denied" in error_msg.lower()
                    ):
                        console.print(
                            f"  [yellow]⚠ {recommender_id.split('.')[-1]}: Insufficient permissions[/]"
                        )
                    elif (
                        "disabled" in error_msg.lower()
                        or "not been used" in error_msg.lower()
                    ):
                        console.print(
                            f"  [yellow]⚠ {recommender_id.split('.')[-1]}: API not enabled[/]"
                        )
                    else:
                        console.print(
                            f"  [yellow]⚠ {recommender_id.split('.')[-1]}: {error_msg[:50]}[/]"
                        )
                    continue

        console.print()

        # Display recommendations
        console.print(Panel("Cost Optimization Recommendations", expand=False))

        if not all_recommendations:
            console.print("[yellow]No recommendations found[/]")
            return

        # Group by recommender
        by_recommender = {}
        for rec in all_recommendations:
            if rec.recommender_id not in by_recommender:
                by_recommender[rec.recommender_id] = []
            by_recommender[rec.recommender_id].append(rec)

        total_savings = sum(
            rec.projected_monthly_savings for rec in all_recommendations
        )

        console.print(
            f"[green]Total potential monthly savings: ${total_savings:,.2f}[/]\n"
        )

        for recommender_id, recommendations in by_recommender.items():
            recommender_table = Table(title=recommender_id)
            recommender_table.add_column("Description", style="cyan")
            recommender_table.add_column("Category", style="blue")
            recommender_table.add_column("Priority", style="yellow")
            recommender_table.add_column("Savings ($)", justify="right", style="green")
            recommender_table.add_column("Affected Resources", style="red")

            for rec in recommendations[:5]:  # Top 5 per recommender
                recommender_table.add_row(
                    rec.description[:80] + "..."
                    if len(rec.description) > 80
                    else rec.description,
                    rec.category,
                    rec.priority,
                    f"${rec.projected_monthly_savings:,.2f}",
                    str(len(rec.affected_resources)),
                )

            console.print(recommender_table)
            console.print()

        log.info(
            "finops.recommendations_complete",
            total_recommendations=len(all_recommendations),
            total_savings=total_savings,
        )

        console.print(
            f"[green]✓ Recommendations generated successfully[/]\n"
            f"Total recommendations: [cyan]{len(all_recommendations)}[/]\n"
            f"Potential monthly savings: [green]${total_savings:,.2f}[/]"
        )

    except Exception as e:
        log.error("finops.recommendations_error", error=str(e))
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@finops_app.command("gke-costs")
def gke_costs_cmd(
    all_projects: bool = typer.Option(
        True, "--all/--no-all", help="Analyze all configured projects (default: true)"
    ),
    project: Optional[str] = typer.Option(
        None, "--project", "-p", help="Specific project ID to analyze"
    ),
    org_id: Optional[str] = typer.Option(
        None, "--org-id", "-o", help="Organization ID (uses config if not specified)"
    ),
    billing_project_id: Optional[str] = typer.Option(
        None,
        "--billing-project",
        "-b",
        help="GCP project with BigQuery billing exports (uses config if not specified)",
    ),
    billing_account_id: Optional[str] = typer.Option(
        None,
        "--billing-account",
        "-a",
        help="Billing account ID (uses config if not specified)",
    ),
    cluster_name: Optional[str] = typer.Option(
        None, "--cluster", help="Specific cluster name to analyze"
    ),
    namespace: Optional[str] = typer.Option(
        None, "--namespace", "-n", help="Filter by namespace"
    ),
    days: int = typer.Option(30, "--days", "-d", help="Number of days to analyze"),
    out_dir: str = typer.Option("gke-cost-report", "--output", help="Output directory"),
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to configuration file"
    ),
):
    """
    Analyze GKE cluster costs with namespace and workload breakdown.

    Can analyze a single project or ALL configured projects.
    Default behavior is to analyze ALL configured projects.

    Requires:
    - GKE Cost Allocation enabled on clusters
    - Cloud Billing export to BigQuery configured

    Configuration values from fulcrum.toml are used as defaults.
    """
    setup_logging()

    # Load config
    settings = load_settings(config)
    defaults = _get_finops_defaults(config)

    # Determine target projects
    target_projects = []
    if project:
        target_projects = [project]
    elif all_projects:
        target_projects = settings.catalog.projects
        if not target_projects:
            console.print(
                "[yellow]Warning: No projects found in configuration. Use --project to specify one.[/]"
            )
    else:
        console.print(
            "[red]Error: Must specify --project or use --all to analyze all configured projects[/]"
        )
        raise typer.Exit(1)

    # Use CLI args or fall back to config defaults
    final_org_id = org_id or defaults["org_id"]
    final_billing_project = billing_project_id or defaults["billing_project_id"]
    final_billing_account = billing_account_id or defaults["billing_account_id"]

    # Validate required parameters
    if not final_billing_project:
        console.print(
            "[red]Error: Billing project ID required for cost analysis.[/]\n\n"
            "This is the GCP project where your Cloud Billing export to BigQuery is configured.\n"
            "Without it, there's no cost data to analyze.\n\n"
            "Setup instructions:\n"
            "  1. Go to Cloud Console > Billing > BigQuery exports\n"
            "  2. Enable billing export to BigQuery in your billing account\n"
            "  3. Note the project ID where exports are stored\n"
            "  4. Set it via: fulcrum finops gke-costs --billing-project PROJECT_ID\n"
            "  5. Or configure in fulcrum.toml: [finops] billing_project_id = 'PROJECT_ID'"
        )
        raise typer.Exit(1)
    if not final_billing_account:
        console.print(
            "[red]Error: Billing account ID required.[/]\n\n"
            "This is your Cloud Billing account ID (format: 123456-789012-3456789).\n"
            "Find it in: Cloud Console > Billing > Account Management\n\n"
            "Set it via: fulcrum finops gke-costs --billing-account ACCOUNT_ID\n"
            "Or configure in fulcrum.toml: [finops] billing_account_id = 'ACCOUNT_ID'"
        )
        raise typer.Exit(1)

    try:
        log.info(
            "finops.gke_costs_start",
            org_id=final_org_id,
            billing_project_id=final_billing_project,
            billing_account_id=final_billing_account,
            cluster_name=cluster_name,
            namespace=namespace,
            days=days,
            target_projects=target_projects,
            all_projects=all_projects,
        )

        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        # Initialize client
        gke_client = GKECostClient(billing_project_id=final_billing_project)

        console.print(
            Panel(
                f"Analyzing GKE costs for {len(target_projects)} project(s)...",
                expand=False,
            )
        )

        # Get comprehensive summary
        gke_summary = gke_client.get_gke_cost_summary(
            billing_account_id=final_billing_account,
            start_date=start_date,
            end_date=end_date,
            project_filter=target_projects if target_projects else None,
        )

        console.print()

        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        # Initialize client
        gke_client = GKECostClient(billing_project_id=final_billing_project)

        console.print(Panel("Analyzing GKE costs...", expand=False))

        # Get comprehensive summary
        gke_summary = gke_client.get_gke_cost_summary(
            billing_account_id=final_billing_account,
            start_date=start_date,
            end_date=end_date,
        )

        console.print()

        # Display cluster costs
        console.print(Panel("GKE Cluster Costs", expand=False))

        cluster_table = Table(title="Cluster Cost Summary")
        cluster_table.add_column("Cluster", style="cyan")
        cluster_table.add_column("Location", style="blue")
        cluster_table.add_column("Total Cost ($)", justify="right", style="green")
        cluster_table.add_column("Nodes", justify="right", style="yellow")
        cluster_table.add_column("Avg Cost/Node", justify="right", style="magenta")

        for cluster in gke_summary.get("clusters", []):
            cluster_table.add_row(
                cluster["cluster_name"],
                cluster["location"],
                f"${cluster['total_cost']:,.2f}",
                str(cluster["node_count"]),
                f"${cluster['avg_cost_per_node']:,.2f}",
            )

        console.print(cluster_table)
        console.print()

        # Display namespace costs
        console.print(Panel("Namespace Cost Breakdown", expand=False))

        namespace_table = Table(title="Namespace Costs")
        namespace_table.add_column("Namespace", style="cyan")
        namespace_table.add_column("Cluster", style="blue")
        namespace_table.add_column("Total Cost ($)", justify="right", style="green")
        namespace_table.add_column("% of Cluster", justify="right", style="yellow")

        for ns in gke_summary.get("namespaces", []):
            namespace_table.add_row(
                ns["namespace"],
                ns["cluster_name"],
                f"${ns['total_cost']:,.2f}",
                f"{ns['percentage_of_cluster']:.1f}%",
            )

        console.print(namespace_table)
        console.print()

        # Display workload costs
        console.print(Panel("Top Workload Costs", expand=False))

        workload_table = Table(title="Workload Cost Summary")
        workload_table.add_column("Workload", style="cyan")
        workload_table.add_column("Type", style="blue")
        workload_table.add_column("Namespace", style="yellow")
        workload_table.add_column("Cluster", style="magenta")
        workload_table.add_column("Total Cost ($)", justify="right", style="green")

        for wl in gke_summary.get("workloads", []):
            workload_table.add_row(
                wl["workload_name"],
                wl["workload_type"],
                wl["namespace"],
                wl["cluster_name"],
                f"${wl['total_cost']:,.2f}",
            )

        console.print(workload_table)
        console.print()

        log.info(
            "finops.gke_costs_complete",
            total_cost=gke_summary.get("total_cost", 0),
            cluster_count=gke_summary.get("cluster_count", 0),
            namespace_count=gke_summary.get("namespace_count", 0),
        )

        console.print(
            f"[green]✓ GKE cost analysis complete[/]\n"
            f"Total GKE cost: [green]${gke_summary.get('total_cost', 0):,.2f}[/]\n"
            f"Clusters analyzed: [cyan]{gke_summary.get('cluster_count', 0)}[/]\n"
            f"Namespaces: [cyan]{gke_summary.get('namespace_count', 0)}[/]"
        )

    except Exception as e:
        log.error("finops.gke_costs_error", error=str(e))
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


def setup_logging():
    """Set up structured logging."""
    import logging

    logging.basicConfig(level=logging.INFO)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO)
    )
