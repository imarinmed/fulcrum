"""Report commands for Fulcrum CLI."""

import asyncio
import os
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

import structlog
import typer
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from ..core.catalog import (
    run_orchestrator,
    safe_copy_dir,
    safe_copy_file,
    validate_csvs,
)
from ..core.logging import setup_logging
from ..core.progress import init_projects, read_state
from ..core.reporting import generate_standard_report, HistoryManager
from ..core.settings import get_cli_defaults, load_settings
from ..core.validator import validate_report
from ..prowler.aggregator import ReportAggregator
from ..prowler.runner import list_checks, run_scan
from ..prowler.scanner import AsyncScanner

console = Console()
log = structlog.get_logger()

# Create Typer app for report commands
report_app = typer.Typer(
    help="Report generation and validation commands",
    no_args_is_help=True,
)


def _get_cli_defaults():
    """Get CLI defaults with fallback values."""
    try:
        return get_cli_defaults()
    except Exception as e:
        log.warning("report.cli_defaults_error", error=str(e), security_event=True)
        return {
            "out_dir": "master-report",
            "summary_path": None,
            "slides_dir": None,
            "projects": [],
        }


async def _wait_for_completion_async(
    report_dir: str, total_checks: int, prog, main_task
):
    """Async version of progress polling loop.

    This replaces the blocking time.sleep(0.1) loop with asyncio.sleep
    for better async integration.
    """
    last_update = time.time()
    updates = {
        "compute": 0,
        "networking": 0,
        "security": 0,
        "storage": 0,
        "sql": 0,
        "gke": 0,
    }
    categories = ["compute", "networking", "security", "storage", "sql", "gke"]

    while not prog.finished:
        current_state = read_state(report_dir)
        if current_state:
            completed = sum(
                1
                for p in current_state
                for cat in categories
                if current_state[p]["categories"][cat]["completed"]
            )
            if completed >= total_checks:
                prog.update(main_task, completed=total_checks)
                break
            prog.update(main_task, completed=completed)

            if time.time() - last_update > 0.5:
                for p in current_state:
                    for cat in categories:
                        if current_state[p]["categories"][cat][
                            "completed"
                        ] and not updates.get(f"{p}_{cat}"):
                            updates[f"{p}_{cat}"] = True
                            log.info(
                                "project_category_completed",
                                project=p,
                                category=cat,
                            )
                last_update = time.time()
        await asyncio.sleep(0.1)


def create_progress_columns():
    """Create Rich progress columns for scanning."""
    return [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
    ]


@report_app.command(
    "report",
    help=(
        "Generate an executive-ready catalog for specified projects. Produces a Markdown "
        "summary, per-category CSVs, IAM matrix, and optional TUI previews."
    ),
)
def report_generate(
    org_id: Optional[str] = typer.Option(
        None, "--org-id", "-g", help="Organization ID", show_default=True
    ),
    projects: List[str] = typer.Option(
        [], "--projects", "-p", help="Project IDs", show_default=True
    ),
    out_dir: str = typer.Option(
        "master-report", "--out-dir", "-o", help="Output directory", show_default=True
    ),
    summary_path: Optional[str] = typer.Option(
        None, "--summary", "-s", help="Copy executive summary to path"
    ),
    slides_dir: Optional[str] = typer.Option(
        None, "--slides", "-l", help="Copy slides to directory"
    ),
    prowler: Optional[bool] = typer.Option(
        False, "--prowler", help="Ingest Prowler findings", is_flag=True
    ),
    prowler_directory: Optional[str] = typer.Option(
        None,
        "--prowler-dir",
        help="Prowler JSON output directory (default: prowler_output)",
    ),
    skip_prowler: Optional[bool] = typer.Option(
        False, "--skip-prowler", help="Skip Prowler scan if already present"
    ),
    max_workers: int = typer.Option(
        10, "--max-workers", "-w", help="Maximum parallel workers for data collection"
    ),
):
    """
    Orchestrate data collection, Prowler scans, and executive report generation.

    This is the main entry point for generating comprehensive GCP resource catalogs
    with security findings and standardized documentation.

    \b
    Examples:
      fulcrum report -g 123456789 -p project-a project-b
      fulcrum report -p project-a --prowler --prowler-dir ./ prowler_output
      fulcrum report -p project-a -o ./my-report --summary ./summary.md
    """
    setup_logging()
    defaults = _get_cli_defaults()

    report_dir = out_dir
    if prowler and not skip_prowler:
        if prowler_directory is None:
            prowler_directory = "prowler_output"
        checks = list_checks()
        if not checks:
            log.error("prowler_not_found")
            console.print(
                "[red]Error: Prowler not found. Install with: pip install prowler"
            )
            raise typer.Exit(1)

        scanner = AsyncScanner(
            projects=projects,
            checks=checks,
            output_directory=prowler_directory,
            max_workers=max_workers,
        )

        with Progress(
            *create_progress_columns(),
            console=console,
            transient=False,
            redirect_stdout=False,
        ) as prog:
            task = prog.add_task("Initializing Prowler scan...", total=None)
            scanner.on(
                "scan:start",
                lambda data: prog.update(task, description=data["msg"], total=None),
            )
            scanner.on("scan:progress", lambda data: prog.advance(task))
            scanner.run()
            prog.update(task, description="Prowler scan complete", completed=True)

        aggregator = ReportAggregator(input_dir=prowler_directory)
        aggregator.run()

    if not projects:
        if defaults.get("projects"):
            projects = defaults["projects"]
        else:
            log.error("no_projects_specified")
            console.print(
                "[red]Error: No projects specified. Use --projects or configure in fulcrum.toml"
            )
            raise typer.Exit(1)

    projects_state = init_projects(projects, report_dir)
    total_projects = len(projects)
    total_checks = len(projects_state) * 6

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as prog:
        main_task = prog.add_task(
            f"[cyan]Collecting GCP metadata for {total_projects} projects...",
            total=total_checks,
        )
        try:
            asyncio.run(
                _wait_for_completion_async(report_dir, total_checks, prog, main_task)
            )
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user[/]")
            raise typer.Exit(0)

    generate_standard_report(projects, report_dir)
    console.print("[green]Report generation completed[/]")

    default_summary = os.path.join(out_dir, "output", "Executive-Summary.md")
    default_slides = os.path.join(out_dir, "slides")
    if summary_path:
        safe_copy_file(default_summary, summary_path)
    if slides_dir:
        safe_copy_dir(default_slides, slides_dir)


@report_app.command(
    "catalog",
    help=(
        "Run a catalog refresh using the current configuration. Ideal for scheduled runs "
        "or quick local updates."
    ),
)
def catalog_refresh(
    out_dir: str = typer.Option("master-report", help="Output directory"),
):
    """
    Refresh catalog based on existing configuration.

    Args:
        out_dir: Destination folder containing config and outputs.
    """
    setup_logging()
    cfg_path = os.path.join(out_dir, "config.yaml")
    run_orchestrator(out_dir, cfg_path)
    console.print("[green]Catalog refresh completed[/]")


@report_app.command(
    "validate",
    help=(
        "Validate inventory outputs for presence, headers, and basic schema. Useful for "
        "data quality gates and CI checks."
    ),
)
def validate_data(
    out_dir: str = typer.Option("master-report", help="Output directory"),
):
    """
    Validate generated artifacts.

    Args:
        out_dir: Destination folder containing CSVs and matrices.
    """
    setup_logging()
    issues = validate_csvs(out_dir)
    if not issues:
        console.print("[green]Validation passed[/]")
    else:
        for i in issues:
            console.print(f"[red]{i}")
        raise typer.Exit(code=1)


@report_app.command(
    "validate-report",
    help=("Validate standardized Markdown report structure, syntax, and links."),
)
def validate_report_cmd(
    path: str = typer.Option("reports", help="Base path or specific report directory"),
):
    setup_logging()
    report_dir = path
    if os.path.isdir(path) and not os.path.isfile(os.path.join(path, "index.md")):
        candidates = [p for p in os.listdir(path) if p.startswith("report-")]
        if candidates:

            def _to_date_token(name: str) -> str:
                try:
                    tok = name.split("-")[-1]
                    if len(tok) == 8 and tok.isdigit():
                        return tok
                    return ""
                except (ValueError, AttributeError) as e:
                    log.debug("report.date_token_error", name=name, error=str(e))
                    return ""

            dated = [(n, _to_date_token(n)) for n in candidates]
            usable = [x for x in dated if x[1]]
            latest = (
                sorted(usable, key=lambda x: x[1])[-1][0]
                if usable
                else sorted(candidates)[-1]
            )
            report_dir = os.path.join(path, latest)
    issues = validate_report(report_dir)
    if not issues:
        console.print(f"[green]Report validation passed[/] -> {report_dir}")
    else:
        for i in issues:
            console.print(f"[red]{i}")
        raise typer.Exit(code=1)
