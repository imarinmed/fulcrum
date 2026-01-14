"""Security commands for Fulcrum CLI."""

import os
from typing import List, Optional

import structlog
import typer
from rich.console import Console
from rich.table import Table

from ..core.logging import setup_logging
from ..core.remediation import RemediationManager
from ..gcp.artifact_registry import migrate_project
from ..gcp.decommission import Decommissioner
from ..gcp.iap_remediation import IAPOAuthRemediation
from ..gcp.logging_quota import analyze_project as analyze_logging
from ..gcp.remediation import GKEReadOnlyPortRemediation
from ..prowler.api import is_api_available, run_scan_api
from ..prowler.runner import list_checks, ProwlerUnavailable, run_scan
from ..prowler.scanner import AsyncScanner
from ..security.audit import SecurityAuditor
from ..security.port_checker import check_port

console = Console()
log = structlog.get_logger()

security_app = typer.Typer(
    help="Security auditing and remediation tools",
    no_args_is_help=True,
)

security_app_no_prowler = typer.Typer(
    help="Security tools that don't require Prowler",
    no_args_is_help=True,
)


@security_app.command("run")
def security_run(
    projects: List[str] = typer.Option(
        [], "--projects", "-p", help="Project IDs to scan"
    ),
    checks: Optional[str] = typer.Option(
        None, "--checks", "-c", help="Comma-separated list of checks"
    ),
    output: str = typer.Option(
        "prowler_output", "--output", "-o", help="Output directory"
    ),
    max_workers: int = typer.Option(
        10, "--max-workers", "-w", help="Maximum parallel workers"
    ),
    api: bool = typer.Option(False, "--api", help="Use Prowler API instead of CLI"),
):
    """
    Run Prowler security scans on projects.

    Performs security assessment using Prowler and generates findings
    that can be ingested into the reporting pipeline.
    """
    setup_logging()

    if not projects:
        log.error("no_projects_specified")
        console.print("[red]Error: No projects specified[/]")
        raise typer.Exit(1)

    if checks:
        check_list = [c.strip() for c in checks.split(",")]
    else:
        check_list = list_checks()
        if not check_list:
            log.error("prowler_not_found")
            console.print(
                "[red]Error: Prowler not found. Install with: pip install prowler[/]"
            )
            raise typer.Exit(1)

    if api:
        if not is_api_available():
            log.error("prowler_api_unavailable")
            console.print("[red]Error: Prowler API not available[/]")
            raise typer.Exit(1)

        for project in projects:
            console.print(f"[cyan]Scanning project: {project}[/]")
            try:
                run_scan_api(project, check_list, output)
                console.print(f"[green]✓ Project {project} scanned[/]")
            except ProwlerUnavailable as e:
                console.print(f"[red]✗ Project {project} failed: {e}[/]")
            except Exception as e:
                log.error("scan_failed", project=project, error=str(e))
                console.print(f"[red]✗ Project {project} failed: {e}[/]")
    else:
        scanner = AsyncScanner(
            projects=projects,
            checks=check_list,
            output_directory=output,
            max_workers=max_workers,
        )
        scanner.run()

    console.print(f"\n[green]Security scan complete[/]")
    console.print(f"Output directory: {output}")


@security_app_no_prowler.command("port-check")
def security_port_check(
    project: str = typer.Argument(..., help="GCP project ID"),
    port: int = typer.Argument(..., help="Port number to check"),
    region: str = typer.Option("global", "--region", "-r", help="GCP region"),
    instance: Optional[str] = typer.Option(
        None, "--instance", "-i", help="Specific instance name"
    ),
):
    """Check if a port is open on instances in a project."""
    setup_logging()

    result = check_port(project, port, region, instance)
    if result.get("reachable"):
        console.print(
            f"[red]Port {port} is REACHABLE on {result.get('count', 0)} instance(s)[/]"
        )
        for instance in result.get("instances", []):
            console.print(f"  - {instance}")
        raise typer.Exit(1)
    else:
        console.print(
            f"[green]Port {port} is NOT reachable (tested {result.get('count', 0)} instances)[/]"
        )


@security_app_no_prowler.command("audit")
def security_audit(
    paths: List[str] = typer.Argument(
        ..., help="Paths to audit for secrets and sensitive data"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output file for findings"
    ),
):
    """Audit local files for secrets and sensitive data."""
    setup_logging()

    # Use first path as root for scanning (multi-path support can be added)
    root_path = paths[0] if len(paths) == 1 else paths
    auditor = SecurityAuditor(root_path=root_path)
    findings = auditor.scan()

    if not findings:
        console.print("[green]No security issues found[/]")
        raise typer.Exit(0)

    table = Table(title="Security Findings")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="magenta")
    table.add_column("Type", style="red")
    table.add_column("Description", style="blue")

    for finding in findings:
        table.add_row(
            finding.get("file", "unknown"),
            str(finding.get("line", "?")),
            finding.get("rule", "secret"),
            finding.get("match_snippet", "")[:50],
        )

    console.print(table)

    if output:
        import json

        with open(output, "w") as f:
            json.dump(findings, f, indent=2)
        console.print(f"\n[green]Findings written to {output}[/]")

    console.print(f"\n[red]Found {len(findings)} potential security issues[/]")
    raise typer.Exit(1)


@security_app_no_prowler.command("iap-fix")
def security_iap_fix(
    project: str = typer.Argument(..., help="GCP project ID"),
    backend: str = typer.Argument(..., help="Backend service name"),
    region: str = typer.Option("global", "--region", "-r", help="GCP region"),
    dry_run: bool = typer.Option(
        True, "--dry-run", help="Show changes without applying"
    ),
):
    """Fix IAP OAuth configuration for a backend service."""
    setup_logging()

    remediation = IAPOAuthRemediation()
    try:
        result = remediation.remediate(project, backend, region, dry_run)
        if result.success:
            console.print("[green]IAP configuration updated[/]")
        else:
            console.print(f"[red]Failed: {result.message}[/]")
            raise typer.Exit(1)
    except Exception as e:
        log.error("iap_fix_failed", error=str(e))
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@security_app_no_prowler.command("gke-readonly-fix")
def security_gke_fix(
    project: str = typer.Argument(..., help="GCP project ID"),
    cluster: str = typer.Argument(..., help="GKE cluster name"),
    region: str = typer.Option("global", "--region", "-r", help="GCP region"),
    dry_run: bool = typer.Option(
        True, "--dry-run", help="Show changes without applying"
    ),
):
    """Fix GKE read-only port exposure."""
    setup_logging()

    remediation = GKEReadOnlyPortRemediation()
    try:
        result = remediation.remediate(
            {"project": project, "cluster": cluster, "region": region},
            dry_run,
        )
        if result.success:
            console.print("[green]GKE security issue remediated[/]")
        else:
            console.print(f"[red]Failed: {result.message}[/]")
            raise typer.Exit(1)
    except Exception as e:
        log.error("gke_fix_failed", error=str(e))
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@security_app_no_prowler.command("migrate-gcr")
def security_migrate_gcr(
    project: str = typer.Argument(..., help="GCP project ID"),
    source_repo: str = typer.Argument(..., help="Source GCR repository"),
    dest_repo: str = typer.Argument(
        ..., help="Destination Artifact Registry repository"
    ),
    dry_run: bool = typer.Option(
        True, "--dry-run", help="Show changes without applying"
    ),
):
    """Migrate images from GCR to Artifact Registry."""
    setup_logging()

    try:
        migrate_project(project, source_repo, dest_repo, dry_run)
        if dry_run:
            console.print("[yellow]Dry run complete - no changes made[/]")
        else:
            console.print("[green]Migration complete[/]")
    except Exception as e:
        log.error("migration_failed", error=str(e))
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@security_app_no_prowler.command("logging-analyze")
def security_logging_analyze(
    project: str = typer.Argument(..., help="GCP project ID"),
):
    """Analyze Cloud Logging configuration and usage."""
    setup_logging()

    try:
        analysis = analyze_logging(project)
        console.print(f"\n[cyan]Logging Analysis for {project}[/]")

        table = Table()
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")

        for key, value in analysis.items():
            table.add_row(key.replace("_", " ").title(), str(value))

        console.print(table)
    except Exception as e:
        log.error("logging_analysis_failed", error=str(e))
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)
