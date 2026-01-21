"""Config commands for Fulcrum CLI."""

import os
from typing import Optional

import structlog
import typer
from rich.console import Console
from rich.table import Table

from ..core.config import load_yaml, merge_config_projects, write_yaml
from ..core.settings import load_settings, save_settings, Settings

console = Console()
log = structlog.get_logger()

config_app = typer.Typer(
    help="Manage Fulcrum TOML configuration",
    no_args_is_help=True,
)


@config_app.command("init")
def config_init(
    config: str = typer.Option(
        "fulcrum.toml", "--config", "-c", help="Path to TOML configuration file"
    ),
):
    """Initialize a minimal configuration file."""
    if os.path.exists(config):
        console.print(f"[yellow]Configuration file '{config}' already exists.[/]")
        raise typer.Exit(1)

    settings = Settings()
    save_settings(settings, config)
    console.print(f"[green]Created configuration file: {config}[/]")


@config_app.command("show")
def config_show(
    config: str = typer.Option(
        "fulcrum.toml", "--config", "-c", help="Path to TOML configuration file"
    ),
):
    """Display the current configuration."""
    settings = load_settings(config)
    table = Table(title="Fulcrum Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Organization ID", settings.org.org_id or "[not set]")
    table.add_row(
        "Projects",
        ", ".join(settings.catalog.projects)
        if settings.catalog.projects
        else "[not set]",
    )
    table.add_row("Output Directory", settings.catalog.output_dir)
    table.add_row("Reports Directory", settings.catalog.reports_dir)

    console.print(table)


@config_app.command("set-org-id")
def config_set_org_id(
    org_id: str,
    config: str = typer.Option(
        "fulcrum.toml", "--config", "-c", help="Path to TOML configuration file"
    ),
):
    """Set the GCP organization ID."""
    settings = load_settings(config)
    settings.org.org_id = org_id
    save_settings(settings, config)
    console.print(f"[green]Set organization ID: {org_id}[/]")


@config_app.command("add-project")
def config_add_project(
    project: str,
    config: str = typer.Option(
        "fulcrum.toml", "--config", "-c", help="Path to TOML configuration file"
    ),
):
    """Add a project to the configuration."""
    settings = load_settings(config)
    if project not in settings.catalog.projects:
        settings.catalog.projects.append(project)
        save_settings(settings, config)
        console.print(f"[green]Added project: {project}[/]")
    else:
        console.print(f"[yellow]Project already exists: {project}[/]")


@config_app.command("remove-project")
def config_remove_project(
    project: str,
    config: str = typer.Option(
        "fulcrum.toml", "--config", "-c", help="Path to TOML configuration file"
    ),
):
    """Remove a project from the configuration."""
    settings = load_settings(config)
    if project in settings.catalog.projects:
        settings.catalog.projects.remove(project)
        save_settings(settings, config)
        console.print(f"[green]Removed project: {project}[/]")
    else:
        console.print(f"[yellow]Project not found: {project}[/]")


@config_app.command("validate")
def config_validate(
    config: str = typer.Option(
        "fulcrum.toml", "--config", "-c", help="Path to TOML configuration file"
    ),
):
    """Validate the configuration file."""
    try:
        settings = load_settings(config)
        console.print("[green]Configuration is valid[/]")

        if not settings.org.org_id:
            console.print("[yellow]Warning: Organization ID not set[/]")
        if not settings.catalog.projects:
            console.print("[yellow]Warning: No projects configured[/]")

    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/]")
        raise typer.Exit(1)


@config_app.command("import")
def config_import(
    source: str = typer.Argument(..., help="Source YAML file to import"),
    config: str = typer.Option(
        "fulcrum.toml", "--config", "-c", help="Path to TOML configuration file"
    ),
):
    """Import projects from a YAML file."""
    yaml_data = load_yaml(source)
    settings = load_settings(config)
    settings = merge_config_projects(settings, yaml_data)
    save_settings(settings, config)
    console.print(f"[green]Imported projects from: {source}[/]")


@config_app.command("auth")
def config_auth(
    config: str = typer.Option(
        "fulcrum.toml", "--config", "-c", help="Path to TOML configuration file"
    ),
):
    """Authenticate with GCP using application default credentials."""
    try:
        authenticate()
        console.print("[green]Authentication successful[/]")
    except Exception as e:
        console.print(f"[red]Authentication failed: {e}[/]")
        raise typer.Exit(1)
