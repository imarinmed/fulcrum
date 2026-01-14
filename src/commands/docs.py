"""Documentation commands for Fulcrum CLI."""

import os
from datetime import datetime, timezone
from typing import Optional

import structlog
import typer
from rich.console import Console
from rich.table import Table

from ..core.docs import (
    build_index,
    generate_asset_summaries,
    generate_kubernetes_csv,
    generate_kubernetes_docs,
    generate_project_tables,
    generate_used_services_summary,
    write_metadata,
)
from ..core.logging import setup_logging
from ..core.reporting import generate_standard_report, HistoryManager
from ..core.settings import load_settings
from ..gcp.logging_quota import analyze_project as analyze_logging

console = Console()
log = structlog.get_logger()

docs_app = typer.Typer(
    help="Generate comprehensive project documentation",
    no_args_is_help=True,
)


@docs_app.command("executive")
def docs_executive(
    out_dir: str = typer.Option("master-report", help="Base output directory"),
    projects: Optional[str] = typer.Option(
        None, "--projects", "-p", help="Comma-separated list of projects"
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing files"),
):
    """
    Generate executive documentation for projects.

    Creates per-project Markdown tables, Kubernetes documentation,
    and used services summary.
    """
    setup_logging()
    settings = load_settings()

    if projects:
        project_list = projects.split(",")
    elif settings.catalog.projects:
        project_list = settings.catalog.projects
    else:
        log.error("no_projects_specified")
        console.print("[red]No projects specified[/]")
        raise typer.Exit(1)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    console.print(
        f"[cyan]Generating executive documentation for {len(project_list)} projects...[/]"
    )

    try:
        generate_project_tables(project_list, out_dir, force)
        console.print("[green]✓ Project tables generated[/]")
    except Exception as e:
        log.error("project_tables_failed", error=str(e))
        console.print(f"[red]✗ Project tables failed: {e}[/]")

    try:
        generate_kubernetes_docs(project_list, out_dir, force)
        console.print("[green]✓ Kubernetes documentation generated[/]")
    except Exception as e:
        log.error("kubernetes_docs_failed", error=str(e))
        console.print(f"[red]✗ Kubernetes docs failed: {e}[/]")

    try:
        generate_kubernetes_csv(project_list, out_dir, force)
        console.print("[green]✓ Kubernetes CSV generated[/]")
    except Exception as e:
        log.error("kubernetes_csv_failed", error=str(e))
        console.print(f"[red]✗ Kubernetes CSV failed: {e}[/]")

    try:
        generate_used_services_summary(project_list, out_dir, force)
        console.print("[green]✓ Used services summary generated[/]")
    except Exception as e:
        log.error("services_summary_failed", error=str(e))
        console.print(f"[red]✗ Services summary failed: {e}[/]")

    try:
        write_metadata(out_dir, timestamp, project_list)
        console.print("[green]✓ Metadata written[/]")
    except Exception as e:
        log.error("metadata_write_failed", error=str(e))
        console.print(f"[red]✗ Metadata write failed: {e}[/]")

    try:
        build_index(out_dir, timestamp, project_list)
        console.print("[green]✓ Index generated[/]")
    except Exception as e:
        log.error("index_build_failed", error=str(e))
        console.print(f"[red]✗ Index build failed: {e}[/]")

    console.print(f"\n[green]Executive documentation complete[/]")
    console.print(f"Output directory: {out_dir}")


@docs_app.command("assets")
def docs_assets(
    out_dir: str = typer.Option("master-report", help="Base output directory"),
    projects: Optional[str] = typer.Option(
        None, "--projects", "-p", help="Comma-separated list of projects"
    ),
):
    """Generate asset summary documentation."""
    setup_logging()
    settings = load_settings()

    if projects:
        project_list = projects.split(",")
    elif settings.catalog.projects:
        project_list = settings.catalog.projects
    else:
        log.error("no_projects_specified")
        console.print("[red]No projects specified[/]")
        raise typer.Exit(1)

    generate_asset_summaries(project_list, out_dir)
    console.print(f"[green]Asset summaries generated in {out_dir}[/]")


@docs_app.command("index")
def docs_index(
    out_dir: str = typer.Option("master-report", help="Base output directory"),
):
    """Build or rebuild the report index."""
    setup_logging()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    settings = load_settings()
    project_list = settings.catalog.projects if settings.catalog.projects else []

    build_index(out_dir, timestamp, project_list)
    console.print(f"[green]Index rebuilt in {out_dir}[/]")


@docs_app.command("history")
def docs_history(
    out_dir: str = typer.Option("master-report", help="Reports directory"),
    limit: int = typer.Option(10, "--limit", "-l", help="Number of entries to show"),
):
    """Show report generation history."""
    setup_logging()

    manager = HistoryManager(out_dir)
    history = manager.get_history()

    if not history:
        console.print("[yellow]No report history found[/]")
        raise typer.Exit(0)

    table = Table(title="Report History")
    table.add_column("Date", style="cyan")
    table.add_column("Projects", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Path", style="blue")

    for entry in sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)[
        :limit
    ]:
        table.add_row(
            entry.get("timestamp", "N/A"),
            ", ".join(entry.get("projects", [])),
            entry.get("status", "unknown"),
            entry.get("_path", "N/A"),
        )

    console.print(table)
