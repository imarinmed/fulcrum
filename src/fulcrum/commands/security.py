"""Security commands for Fulcrum CLI."""

import asyncio
import os
import logging
from typing import List, Optional

import structlog
import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table

from ..core.logging import setup_logging
from ..core.remediation import RemediationManager
from ..core.settings import load_settings
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
from ..ui.scan_dashboard import ScanDashboard

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


@security_app.command("scan")
def security_scan(
    all_projects: bool = typer.Option(
        True, "--all/--no-all", help="Scan all configured projects"
    ),
    project: Optional[str] = typer.Option(
        None, "--project", "-p", help="Specific project ID to scan"
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
    timeout: Optional[int] = typer.Option(
        None, "--timeout", "-t", help="Scan timeout in seconds"
    ),
    api: bool = typer.Option(False, "--api", help="Use Prowler API instead of CLI"),
    config: Optional[str] = typer.Option(
        None, "--config", help="Path to configuration file"
    ),
):
    """
    Scan infrastructure for security vulnerabilities.

    Can scan a single project or all projects defined in configuration.
    Default behavior is to scan ALL configured projects.
    """
    setup_logging()

    settings = load_settings(config)
    target_projects = []

    if project:
        target_projects = [project]
    elif all_projects:
        target_projects = settings.catalog.projects
        if not target_projects:
            console.print("[yellow]Warning: No projects found in configuration[/]")
            raise typer.Exit(1)
    else:
        console.print("[red]Error: Must specify --project or --all[/]")
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
        base_url = settings.security.api_url
        token = settings.security.api_token

        if not is_api_available(base_url, token):
            log.error("prowler_api_unavailable")
            console.print("[red]Error: Prowler API not available[/]")
            raise typer.Exit(1)

        for proj in target_projects:
            console.print(f"[cyan]Scanning project: {proj}[/]")
            try:
                run_scan_api(
                    base_url=base_url,
                    token=token,
                    provider="gcp",
                    projects=[proj],
                    org_id=settings.org.org_id,
                )
                console.print(f"[green]✓ Project {proj} scanned[/]")
            except ProwlerUnavailable as e:
                console.print(f"[red]✗ Project {proj} failed: {e}[/]")
            except Exception as e:
                log.error("scan_failed", project=proj, error=str(e))
                console.print(f"[red]✗ Project {proj} failed: {e}[/]")
    else:
        # Redirect logs to file to keep UI clean
        log_file = "security-scan.log"
        # Force reconfig of basic logging to file
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(filename=log_file, level=logging.INFO, force=True)

        console.print(f"[dim]Detailed logs redirected to {log_file}[/]")

        # Determine timeout: arg > config > default(600)
        final_timeout = (
            timeout if timeout is not None else settings.security.timeout_sec
        )

        scanner = AsyncScanner(
            output_dir=output,
            max_concurrency=max_workers,
            timeout_sec=final_timeout,
        )

        dashboard = ScanDashboard(target_projects)

        async def run_with_ui():
            with Live(dashboard.get_renderable(), refresh_per_second=10) as live:

                async def refresh_loop():
                    """Force dashboard refresh to update timers and progress."""
                    while True:
                        live.update(dashboard.get_renderable())
                        await asyncio.sleep(0.1)

                async def scan_wrapper(pid):
                    dashboard.update_project(pid, "Scanning")
                    # No need to manual update here, refresh_loop handles it

                    result = await scanner.scan_project(pid)

                    status = "Done" if result.success else "Error"
                    if result.error and "Timeout" in str(result.error):
                        status = "Timeout"

                    dashboard.update_project(pid, status, result=result.success)
                    return result

                refresh_task = asyncio.create_task(refresh_loop())
                tasks = [scan_wrapper(p) for p in target_projects]
                try:
                    await asyncio.gather(*tasks)
                finally:
                    refresh_task.cancel()
                    try:
                        await refresh_task
                    except asyncio.CancelledError:
                        pass

        asyncio.run(run_with_ui())

    console.print(f"\n[green]Security scan complete[/]")
    console.print(f"Output directory: {output}")


@security_app.command("run")
def security_run(
    projects: List[str] = typer.Option(
        [], "--projects", "-p", help="Deprecated. Use 'scan' instead."
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
    Deprecated: Use 'scan' instead.
    """
    console.print("[yellow]Warning: 'run' command is deprecated. Please use 'scan'.[/]")
    # Redirect to scan logic if needed, but for now just warn or fail.
    # Or map arguments and call security_scan.
    # To avoid complexity, we'll just error and tell user to use scan.
    raise typer.Exit(1)


@security_app_no_prowler.command("port-check")
def security_port_check(
    project: str = typer.Argument(..., help="GCP project ID"),
    port: int = typer.Argument(..., help="Port number to check"),
    # Removing unsupported region/instance args from underlying call
    region: str = typer.Option(
        "global", "--region", "-r", help="Ignored (not supported by checker)"
    ),
    instance: Optional[str] = typer.Option(
        None, "--instance", "-i", help="Ignored (not supported by checker)"
    ),
):
    """Check if a port is open in a project (checking firewall rules)."""
    setup_logging()

    if region != "global" or instance:
        console.print(
            "[yellow]Warning: region and instance arguments are currently ignored by the port checker.[/]"
        )

    # check_port expects list of projects and prints results itself
    check_port([project], port)


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

    # Use first path as root for scanning
    root_path: str = paths[0] if paths else "."
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
