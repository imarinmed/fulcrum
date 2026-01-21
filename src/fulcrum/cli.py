"""
Fulcrum CLI — Main entry point.

This module provides the CLI interface for generating executive-grade
catalogs and standardized reports from GCP assets.

Commands are organized into sub-modules:
- report: Report generation and validation
- config: Configuration management
- docs: Executive documentation generation
- security: Security scanning and remediation
"""

import os
from typing import List, Optional

import structlog
import typer
from rich.console import Console

from .commands.config import config_app
from .commands.docs import docs_app
from .commands.finops import finops_app
from .commands.report import report_app
from .commands.security import security_app, security_app_no_prowler
from .core.logging import setup_logging
from .core.settings import load_settings
from .ui.app import launch

# Initialize structured logging
log = structlog.get_logger()

# Create main Typer application
app = typer.Typer(
    help=(
        "Fulcrum CLI — generate catalogs and standardized reports from GCP assets.\n\n"
        "Highlights:\n"
        "- Standard reports include Compute, Networking, Security, Storage, Data Storage (Cloud SQL), and Kubernetes (GKE).\n"
        "- Executive docs include per‑project tables, Kubernetes catalog, and Used Services summary.\n"
        "- Integrations: Prowler security results ingestion and formatting."
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)

console = Console()

# Register sub-command groups
app.add_typer(config_app, name="config", help="Manage Fulcrum TOML configuration")
app.add_typer(docs_app, name="docs", help="Generate executive documentation")
app.add_typer(finops_app, name="finops", help="FinOps and cost management reports")
app.add_typer(report_app, name="report", help="Report generation and validation")
app.add_typer(security_app, name="security", help="Security scanning and remediation")
app.add_typer(
    security_app_no_prowler, name="security-local", help="Local security tools (no GCP)"
)


@app.callback()
def main_callback(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose output"
    ),
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to configuration file"
    ),
):
    """
    Main callback for global setup.
    """
    if verbose:
        import logging

        logging.basicConfig(level=logging.DEBUG)
        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG)
        )


@app.command("dashboard")
def dashboard_cmd(
    out_dir: str = typer.Option("master-report", help="Output directory"),
):
    """Launch the interactive TUI dashboard."""
    setup_logging()
    try:
        launch(out_dir)
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard closed[/]")


@app.command("version")
def version_cmd():
    """Show version information."""
    try:
        from . import __version__

        console.print(f"Fulcrum version: [cyan]{__version__}[/]")
    except ImportError:
        console.print("[red]Unable to determine version[/]")


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
