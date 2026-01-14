from typing import List, Optional
import asyncio
import csv
import glob
import json
import os
import re
import resource
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone

import psutil
import structlog
import typer
from rich import box
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

from .core.backup import BackupOrchestrator
from .core.catalog import (
    run_orchestrator,
    safe_copy_dir,
    safe_copy_file,
    validate_csvs,
)
from .core.config import load_yaml, merge_config_projects, write_yaml
from .core.diagnostics import DiagnosticsManager
from .core.docs import (
    build_index,
    generate_asset_summaries,
    generate_kubernetes_csv,
    generate_kubernetes_docs,
    generate_project_tables,
    generate_used_services_summary,
    write_metadata,
)
from .core.logging import setup_logging
from .core.progress import init_projects, read_state
from .core.remediation import RemediationManager
from .core.reporting import generate_standard_report, HistoryManager
from .core.settings import Settings, get_cli_defaults, load_settings, save_settings
from .core.validator import validate_report
from .gcp.artifact_registry import migrate_project
from .gcp.decommission import Decommissioner
from .gcp.iap_remediation import IAPOAuthRemediation
from .gcp.logging_quota import analyze_project as analyze_logging
from .gcp.remediation import GKEReadOnlyPortRemediation
from .prowler.aggregator import ReportAggregator
from .prowler.api import is_api_available, run_scan_api
from .prowler.runner import list_checks, ProwlerUnavailable, run_scan
from .prowler.scanner import AsyncScanner
from .security.audit import SecurityAuditor
from .security.port_checker import check_port
from .ui.app import launch

app = typer.Typer(
    help=(
        "Fulcrum CLI — generate catalogs and standardized reports from GCP assets.\n\n"
        "Highlights:\n"
        "- Standard reports include Compute, Networking, Security, Storage, Data Storage (Cloud SQL), and Kubernetes (GKE).\n"
        "- Executive docs include per‑project tables, Kubernetes catalog, and Used Services summary.\n"
        "- Integrations: Prowler security results ingestion and formatting."
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()


@app.command(
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
        None, help="Destination path for Executive Summary Markdown", show_default=True
    ),
    slides_dir: Optional[str] = typer.Option(
        None, help="Destination directory for slides", show_default=True
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable detailed logging", show_default=True
    ),
    redact: bool = typer.Option(
        True, help="Enable stakeholder redaction", show_default=True
    ),
):
    """
    Description:
        Generate a rich executive catalog across selected projects, writing CSVs, IAM matrices and previews.

    Parameters:
        - org_id (optional, str): Organization ID. Example: "1234567890".
        - projects (optional, list[str]): Project IDs. Example: "p1 p2".
        - out_dir (optional, str): Output directory. Default: "master-report".
        - summary_path (optional, str): Destination for Executive Summary Markdown.
        - slides_dir (optional, str): Destination for slides directory.
        - verbose (optional, bool): Enable detailed logging.
        - redact (optional, bool): Apply stakeholder-safe redaction.

    Usage:
        fulcrum report --org-id 1234567890 --projects p1 p2 --out-dir master-report

    Troubleshooting:
        Ensure `out_dir/scripts/generate_catalog.py` exists and credentials permit listing resources.
    """
    setup_logging()
    s = load_settings(None)
    if not projects:
        projects = s.catalog.projects
    if not org_id:
        org_id = s.org.org_id
    if not summary_path:
        summary_path = s.output.summary_path
    if not slides_dir:
        slides_dir = s.output.slides_dir
    cfg_path = os.path.join(out_dir, "config.yaml")
    cfg = load_yaml(cfg_path)
    merged = merge_config_projects(cfg, org_id, projects, redact)
    # Write merged settings directly to the generator's config.yaml
    write_yaml(cfg_path, merged)
    progress_path = os.path.join(out_dir, "tmp", "progress.json")
    init_projects(progress_path, projects, ["Resources", "IAM"])
    with Progress(
        SpinnerColumn(),
        TextColumn(
            "[bold]{task.fields[project]}[/] {task.fields[phase]} {task.fields[detail]}",
            justify="left",
        ),
        BarColumn(),
        TextColumn("{task.percentage:>5.2f}%"),
        TimeRemainingColumn(),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=5,
    ) as progress:
        project_tasks = {}
        palette = ["cyan", "magenta", "yellow", "green", "blue", "white"]
        for i, pid in enumerate(projects):
            color = palette[i % len(palette)]
            for ph in ["Resources", "IAM"]:
                project_tasks[(pid, ph)] = progress.add_task(
                    "proj",
                    total=100.0,
                    project=pid,
                    phase=ph,
                    detail="pending",
                    style=color,
                )
        env = dict(os.environ)
        env["PROGRESS_PATH"] = progress_path
        env["TMPDIR"] = os.path.join(out_dir, "tmp")
        os.makedirs(env["TMPDIR"], exist_ok=True)
        proc = subprocess.Popen(
            [
                os.environ.get("PYTHON", sys.executable),
                os.path.join(out_dir, "scripts", "generate_catalog.py"),
            ],
            env=env,
        )
        while True:
            st = read_state(progress_path)
            for pid, pdata in st.get("projects", {}).items():
                for ph, pstate in pdata.get("phases", {}).items():
                    task_id = project_tasks.get((pid, ph))
                    if task_id is not None:
                        progress.update(
                            task_id,
                            completed=pstate.get("progress", 0.0),
                            detail=pstate.get("eta", "--"),
                        )
            if proc.poll() is not None:
                break
            time.sleep(0.5)
    console.print("[green]Report generation completed[/]")
    from .core.catalog import safe_copy_file, safe_copy_dir

    default_summary = os.path.join(out_dir, "output", "Executive-Summary.md")
    default_slides = os.path.join(out_dir, "slides")
    if summary_path:
        safe_copy_file(default_summary, summary_path)
    if slides_dir:
        safe_copy_dir(default_slides, slides_dir)


@app.command(
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


@app.command(
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


@app.command(
    "validate-report",
    help=("Validate standardized Markdown report structure, syntax, and links."),
)
def validate_report_cmd(
    path: str = typer.Option("reports", help="Base path or specific report directory"),
):
    setup_logging()
    report_dir = path
    if os.path.isdir(path) and not os.path.isfile(os.path.join(path, "index.md")):
        # try latest typed or legacy report inside base path
        candidates = [p for p in os.listdir(path) if p.startswith("report-")]
        if candidates:

            def _to_date_token(name: str) -> str:
                try:
                    tok = name.split("-")[-1]
                    if len(tok) == 8 and tok.isdigit():
                        return tok
                    return ""
                except Exception:
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


@app.command(
    "dashboard",
    help=(
        "Launch a Textual-powered TUI to explore inventories with sortable tables and "
        "responsive layout."
    ),
)
def dashboard_demo(
    out_dir: str = typer.Option("master-report", help="Output directory"),
):
    """
    Open the interactive dashboard.

    Args:
        out_dir: Destination folder with CSV inventories.
    """
    from .ui.app import launch

    launch(out_dir)


config_app = typer.Typer(help="Manage Fulcrum TOML configuration")
app.add_typer(config_app, name="config")


@config_app.command("init")
def config_init(config: str = typer.Option(None, help="Path to create fulcrum.toml")):
    setup_logging()
    path = save_settings(config, Settings())
    console.print(f"[green]Initialized config at {path}[/]")


@config_app.command("show")
def config_show(config: str = typer.Option(None, help="Path to read fulcrum.toml")):
    setup_logging()
    s = load_settings(config)
    console.print(s.model_dump())


@config_app.command("set-org-id")
def config_set_org_id(
    org_id: str, config: str = typer.Option(None, help="Path to fulcrum.toml")
):
    setup_logging()
    s = load_settings(config)
    s.org.org_id = org_id
    path = save_settings(config, s)
    console.print(f"[green]Updated org_id in {path}[/]")


@config_app.command("add-project")
def config_add_project(
    project_id: str, config: str = typer.Option(None, help="Path to fulcrum.toml")
):
    setup_logging()
    s = load_settings(config)
    if project_id not in s.catalog.projects:
        s.catalog.projects.append(project_id)
    path = save_settings(config, s)
    console.print(f"[green]Added project to {path}[/]")


@config_app.command("remove-project")
def config_remove_project(
    project_id: str, config: str = typer.Option(None, help="Path to fulcrum.toml")
):
    setup_logging()
    s = load_settings(config)
    s.catalog.projects = [p for p in s.catalog.projects if p != project_id]
    path = save_settings(config, s)
    console.print(f"[green]Removed project in {path}[/]")


@config_app.command("set-timeout")
def config_set_timeout(
    seconds: int, config: str = typer.Option(None, help="Path to fulcrum.toml")
):
    setup_logging()
    s = load_settings(config)
    s.catalog.timeout_sec = seconds
    path = save_settings(config, s)
    console.print(f"[green]Updated timeout_sec in {path}[/]")


@config_app.command("set-limit")
def config_set_limit(
    limit: int, config: str = typer.Option(None, help="Path to fulcrum.toml")
):
    setup_logging()
    s = load_settings(config)
    s.catalog.limit_per_project = limit
    path = save_settings(config, s)
    console.print(f"[green]Updated limit_per_project in {path}[/]")


@config_app.command("set-redaction")
def config_set_redaction(
    enable: bool = typer.Option(True),
    config: str = typer.Option(None, help="Path to fulcrum.toml"),
):
    setup_logging()
    s = load_settings(config)
    s.redaction.enabled = enable
    path = save_settings(config, s)
    console.print(f"[green]Updated redaction.enabled in {path}[/]")


@app.command("executive")
def build_executive(
    out_dir: str = typer.Option("master-report", help="Catalog output directory"),
    exec_out: Optional[str] = typer.Option(
        None, help="Destination directory for executive report"
    ),
):
    setup_logging()
    env = dict(os.environ)
    if exec_out:
        env["EXEC_OUT"] = exec_out
    cmd = [
        os.environ.get("PYTHON", sys.executable),
        os.path.join(out_dir, "scripts", "build_executive_report.py"),
    ]
    subprocess.run(cmd, check=True, env=env)
    console.print("[green]Executive report generated[/]")


docs_app = typer.Typer(help="Generate comprehensive project documentation")
app.add_typer(docs_app, name="docs")


@docs_app.command(
    "generate",
    help=(
        "Generate comprehensive per‑project documentation, Kubernetes catalog, and summaries.\n\n"
        "Example:\n  fulcrum docs generate --out-dir master-report"
    ),
)
def docs_generate(
    out_dir: str = typer.Option(
        "master-report",
        "--out-dir",
        "-o",
        help="Catalog output directory",
        show_default=True,
    ),
    author: Optional[str] = typer.Option(
        None, "--author", "-a", help="Author attribution", show_default=True
    ),
):
    setup_logging()
    s = load_settings(None)
    author = author or s.metadata.author
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Building documentation[/]"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("build", total=6)
        project_index = generate_project_tables(
            out_dir, all_projects=s.catalog.projects
        )
        from .core.docs import (
            generate_asset_summaries,
            generate_used_services_summary,
            generate_kubernetes_csv,
        )

        generate_asset_summaries(out_dir)
        progress.advance(task)
        generate_used_services_summary(out_dir)
        progress.advance(task)
        kube_index = generate_kubernetes_docs(out_dir, author)
        progress.advance(task)
        generate_kubernetes_csv(out_dir)
        progress.advance(task)
        index_path = build_index(out_dir, author, project_index, kube_index)
        progress.advance(task)
        write_metadata(
            out_dir, author, s.metadata.version, s.org.org_id, s.catalog.projects
        )
        progress.advance(task)
    console.print(
        f"[green]Documentation generated[/] -> {os.path.join(out_dir, 'executive', 'index.md')}"
    )


reports_app = typer.Typer(help="Generate standardized Markdown reports")
app.add_typer(reports_app, name="reports")


@reports_app.command(
    "standard",
    help=(
        "Generate a standardized Markdown report (dated) across selected projects, including "
        "Compute, Networking, Security, Storage, Data Storage (Cloud SQL), and Kubernetes (GKE).\n\n"
        "Examples:\n"
        "  fulcrum reports standard --out-base reports\n"
        "  fulcrum reports standard --out-base reports --report-date 20250101\n"
        "  fulcrum reports standard --out-base reports --sa-key key.json --prowler-json prowler.json\n"
    ),
)
def reports_standard(
    out_base: str = typer.Option(
        "reports",
        "--out-base",
        "-o",
        help="Base directory for standardized reports",
        show_default=True,
    ),
    report_date: Optional[str] = typer.Option(
        None, "--report-date", "-d", help="UTC date in YYYYMMDD", show_default=True
    ),
    author: Optional[str] = typer.Option(
        None, "--author", "-a", help="Author attribution", show_default=True
    ),
    version: Optional[str] = typer.Option(
        "1.0.0", "--version", "-V", help="Report version", show_default=True
    ),
    sa_key: Optional[str] = typer.Option(
        None,
        "--sa-key",
        "-k",
        help="Path to service account JSON credentials",
        show_default=True,
    ),
    formats: List[str] = typer.Option(
        ["md", "json", "csv"], help="Output formats to produce", show_default=True
    ),
    prowler_json: Optional[str] = typer.Option(
        None, help="Path to Prowler JSON results", show_default=True
    ),
    prowler_csv: Optional[str] = typer.Option(
        None, help="Path to Prowler CSV results", show_default=True
    ),
):
    """
    Description:
        Collect GCP resources and produce a standardized report with Kubernetes, networking, compute, storage and security.

    Parameters:
        - out_base (optional, str): Output base directory. Default: "reports".
        - report_date (optional, str): UTC date YYYYMMDD. Default: current UTC.
        - author (optional, str): Author attribution. Default: value in TOML or "Iñaki Marín".
        - version (optional, str): Report version tag.
        - sa_key (optional, str): Path to service account credentials JSON.
        - formats (optional, list[str]): Output formats to produce.
        - prowler_json/prowler_csv (optional, str): Prowler results to ingest.

    Usage:
        fulcrum reports standard --out-base reports

    Errors:
        Invalid credentials or API permissions may prevent collection. Ensure Container API access for GKE.
    """
    setup_logging()
    s = load_settings(None)
    d = get_cli_defaults(s)
    author = author or d["author"]
    report_date = report_date or d["report_date"]
    if out_base == "reports":
        out_base = d["out_base"]
    if formats == ["md", "json", "csv"]:
        formats = d["formats"]
    sa_key = sa_key or d.get("sa_key")
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Collecting GCP data[/]"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("collect", total=1)
        res = generate_standard_report(
            out_base,
            author,
            report_date,
            version or s.metadata.version,
            sa_key,
            prowler_json,
            prowler_csv,
            rtype="std",
        )
        progress.advance(task)
    console.print(f"[green]Standard report generated[/] -> {res['report_dir']}")
    console.print(
        "[cyan]Sections:\n - Compute\n - Networking\n - Security (with optional Prowler)\n - Storage\n - Data Storage (Cloud SQL)\n - Kubernetes (GKE)\n - Index & metadata\n"
    )


@reports_app.command(
    "migrate-names",
    help=(
        "Rename legacy report directories from 'report-YYYYMMDD' to typed names 'report-std-YYYYMMDD' or 'report-sec-YYYYMMDD'."
    ),
)
def reports_migrate_names(
    out_base: str = typer.Option(
        "reports", "--out-base", "-o", help="Base output directory", show_default=True
    ),
):
    setup_logging()
    if not os.path.isdir(out_base):
        console.print(f"[yellow]Base directory not found[/] -> {out_base}")
        raise typer.Exit(code=1)
    entries = [
        d
        for d in os.listdir(out_base)
        if d.startswith("report-") and os.path.isdir(os.path.join(out_base, d))
    ]
    changed = []
    for name in sorted(entries):
        if name.startswith("report-std-") or name.startswith("report-sec-"):
            continue
        parts = name.split("-")
        date_tok = parts[-1] if parts else ""
        if not (len(date_tok) == 8 and date_tok.isdigit()):
            continue
        src = os.path.join(out_base, name)
        # classify type: presence of prowler outputs implies security
        t = (
            "sec"
            if (
                os.path.isfile(os.path.join(src, "data", "prowler.csv"))
                or os.path.isfile(os.path.join(src, "data", "prowler.json"))
            )
            else "std"
        )
        dest = os.path.join(out_base, f"report-{t}-{date_tok}")
        if os.path.abspath(src) == os.path.abspath(dest):
            continue
        if os.path.exists(dest):
            # append numeric suffix until free
            suffix = 2
            while os.path.exists(f"{dest}-{suffix:02d}"):
                suffix += 1
            dest = f"{dest}-{suffix:02d}"
        try:
            os.rename(src, dest)
            changed.append((name, os.path.basename(dest)))
            console.print(f"[green]Renamed[/] {name} -> {os.path.basename(dest)}")
        except Exception as e:
            console.print(f"[yellow]Skipped[/] {name} ({e})")
    if not changed:
        console.print("[cyan]No legacy directories to migrate[/]")
    else:
        console.print(f"[green]Migration complete[/] ({len(changed)} directories)")


schedule_app = typer.Typer(help="Scheduling helpers for report generation")
app.add_typer(schedule_app, name="schedule")


@schedule_app.command("reports")
def schedule_reports(
    cadence: str = typer.Option("weekly", help="Cadence: daily|weekly|monthly"),
    out_base: str = typer.Option("reports", help="Base output directory"),
):
    setup_logging()
    if cadence not in {"daily", "weekly", "monthly"}:
        raise typer.BadParameter("cadence must be daily, weekly, or monthly")
    console.print("[cyan]To schedule, add a cron entry like:[/]")
    if cadence == "daily":
        console.print(f"0 2 * * * fulcrum reports standard --out-base {out_base}")
    elif cadence == "weekly":
        console.print(f"0 2 * * 1 fulcrum reports standard --out-base {out_base}")
    else:
        console.print(f"0 2 1 * * fulcrum reports standard --out-base {out_base}")


security_app = typer.Typer(
    help=(
        "Security scanning and reporting\n\n"
        "Commands:\n"
        "  run      → Execute Prowler (CLI or API) and attach results to the report\n"
        "  scan     → Run infrastructure or code scans\n"
        "  report   → Generate security reports from scan results\n"
        "  fix      → Apply security fixes to resources\n"
        "  audit    → Run security audits and compliance checks\n"
        "  port     → Check port status across projects"
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
)
reports_app.add_typer(security_app, name="security")


@security_app.command(
    "run",
    help=(
        "Run a Prowler security scan and integrate results into the standardized report. "
        "Supports local CLI or Prowler App API."
    ),
)
def security_run(
    provider: str = typer.Option(
        "gcp", "--provider", help="Cloud provider", show_default=True
    ),
    projects: List[str] = typer.Option(
        [], "--projects", "-p", help="Project IDs", show_default=True
    ),
    org_id: Optional[str] = typer.Option(
        None, "--org-id", "-g", help="Organization ID", show_default=True
    ),
    sa_key: Optional[str] = typer.Option(
        None, "--sa-key", "-k", help="Path to service account JSON", show_default=True
    ),
    out_base: str = typer.Option(
        "reports", "--out-base", "-o", help="Base output directory", show_default=True
    ),
    report_date: Optional[str] = typer.Option(
        None, "--report-date", "-d", help="UTC date in YYYYMMDD", show_default=True
    ),
    formats: List[str] = typer.Option(
        ["md", "json", "csv"], "--formats", help="Output formats", show_default=True
    ),
    prowler_bin: Optional[str] = typer.Option(
        None, "--prowler-bin", help="Path to prowler binary", show_default=True
    ),
    prowler_json: Optional[str] = typer.Option(
        None, "--prowler-json", help="Path to Prowler JSON output", show_default=True
    ),
    prowler_csv: Optional[str] = typer.Option(
        None, "--prowler-csv", help="Path to Prowler CSV output", show_default=True
    ),
    api_url: Optional[str] = typer.Option(
        None, "--api-url", help="Base URL for Prowler App API", show_default=True
    ),
    api_token: Optional[str] = typer.Option(
        None, "--api-token", help="Token for Prowler App API", show_default=True
    ),
):
    """
    Description:
        Execute a Prowler security scan and attach findings to the standardized report.

    Parameters:
        - provider (optional, str): Cloud provider. Default: "gcp".
        - projects (optional, list[str]): Project IDs to scan.
        - org_id (optional, str): Organization ID context.
        - sa_key (optional, str): Path to service account credentials JSON.
        - out_base (optional, str): Base output directory for reports.
        - report_date (optional, str): UTC date YYYYMMDD. Default: current UTC.
        - formats (optional, list[str]): Output formats to produce.
        - prowler_bin (optional, str): Prowler CLI path when not using API.
        - prowler_json/prowler_csv (optional, str): Paths to pre-generated Prowler outputs.
        - api_url/api_token (optional, str): Prowler App API endpoint and token.

    Usage:
        fulcrum reports security run --provider gcp --projects p1 p2 --out-base reports

    Troubleshooting:
        Ensure credentials and permissions allow scanning; if API is unavailable the CLI path is used.
    """
    setup_logging()
    s = load_settings(None)
    d = get_cli_defaults(s)
    report_date = report_date or d["report_date"]
    projects = projects or d["projects"]
    org_id = org_id or d["org_id"]
    if out_base == "reports":
        out_base = d["out_base"]
    if formats == ["md", "json", "csv"]:
        formats = d["formats"]
    prowler_bin = prowler_bin or d["prowler_bin"]
    if api_url is None:
        api_url = d["api_url"]
    if api_token is None:
        api_token = d["api_token"]
    sa_key = sa_key or d["sa_key"]
    # Preflight checks
    issues = []
    if not projects:
        issues.append(
            "No projects configured. Set catalog.projects in fulcrum.toml or pass --projects."
        )
    try:
        if prowler_bin and not os.path.exists(prowler_bin):
            issues.append(f"Prowler binary not found at {prowler_bin}")
        elif prowler_bin and not os.access(prowler_bin, os.X_OK):
            issues.append(f"Prowler binary at {prowler_bin} is not executable")
    except Exception:
        issues.append("Unable to validate prowler binary path")
    if not os.path.isdir(out_base):
        try:
            os.makedirs(out_base, exist_ok=True)
        except Exception:
            issues.append(f"Cannot create output directory {out_base}")
    if sa_key and not os.path.exists(sa_key):
        issues.append(f"Service account key not found at {sa_key}")
    if issues:
        for i in issues:
            console.print(f"[red]{i}")
        raise typer.Exit(code=1)
    ran_via_api = False
    if api_url:
        try:
            APIUnavailable = ProwlerUnavailable
            if is_api_available(api_url, api_token):
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold]Running Prowler API scan[/]"),
                    BarColumn(),
                    TimeElapsedColumn(),
                    console=console,
                ) as progress:
                    task = progress.add_task("api", total=1)
                    res_api = run_scan_api(
                        api_url, api_token, provider, projects, org_id or s.org.org_id
                    )
                    progress.advance(task)
                data_dir = os.path.join(out_base, f"report-sec-{report_date}", "data")
                os.makedirs(data_dir, exist_ok=True)
                with open(os.path.join(data_dir, "prowler.json"), "w") as f:
                    f.write(res_api.get("results", "[]"))
                console.print("[green]Prowler API scan completed[/]")
                ran_via_api = True
            else:
                console.print("[yellow]Prowler API unavailable, falling back to CLI[/]")
        except APIUnavailable as e:
            console.print(f"[yellow]{e}[/]")
    if not ran_via_api:
        try:
            checks = list_checks(provider, prowler_bin)
            total_checks = (len(checks) or 0) * max(len(projects), 1)
            from rich.live import Live
            from rich.table import Table
            from rich import box
            from rich.progress import (
                Progress,
                SpinnerColumn,
                BarColumn,
                TextColumn,
                TimeElapsedColumn,
                TimeRemainingColumn,
            )
            from rich.align import Align
            from rich.panel import Panel
            import threading
            import time
            import resource

            start = time.time()
            status = {
                "completed": 0,
                "failed": 0,
                "running": 0,
                "last": "",
                "last_level": "",
                "last_module": "",
                "errors": 0,
                "log_size": 0,
                "log_age": "-",
                "activity": "Active",
                "events": deque(maxlen=12),
            }

            def _to_iso(ts: str) -> str:
                try:
                    if "T" in ts:
                        return ts
                    y = int(ts[0:4])
                    m = int(ts[5:7])
                    d = int(ts[8:10])
                    hh = int(ts[11:13])
                    mm_ = int(ts[14:16])
                    ss = int(ts[17:19])
                    return f"{y:04d}-{m:02d}-{d:02d}T{hh:02d}:{mm_:02d}:{ss:02d}Z"
                except Exception:
                    return ts

            def _classify(msg: str, mod: str) -> str:
                ml = (msg or "").lower()
                if "executing" in ml and "checks" in ml:
                    return "start_checks"
                if "instantiating gcp provider" in ml:
                    return "init"
                if "service_disabled" in ml or (
                    "has not been used" in ml and "disabled" in ml
                ):
                    return "service_disabled"
                if "forbidden" in ml or "permission_denied" in ml:
                    return "permission_error"
                if "http" in (mod or "").lower():
                    return "http"
                return "info"

            prog = Progress(
                SpinnerColumn(spinner_name="dots"),
                TextColumn("[bold]Scan[/]"),
                BarColumn(bar_width=40),
                TextColumn("{task.percentage:>5.1f}%"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=False,
                expand=True,
            )
            task_overall = prog.add_task("overall", total=total_checks)
            # CPU sampling state
            last_wall = start
            r = resource.getrusage(resource.RUSAGE_SELF)
            last_cpu = float(getattr(r, "ru_utime", 0.0) + getattr(r, "ru_stime", 0.0))

            def metrics_table():
                elapsed = time.time() - start
                pct = (
                    (status["completed"] / total_checks * 100.0)
                    if total_checks
                    else 0.0
                )
                t = Table(box=box.SIMPLE, expand=True)
                t.add_column("Metric")
                t.add_column("Value")
                t.add_row("Elapsed", f"{int(elapsed)}s")
                # Progress bar is primary indicator; omit redundant textual progress/ETA/running/failed rows
                t.add_row("Log Size", f"{status['log_size']} bytes")
                t.add_row("Last Log Update", status["log_age"])
                t.add_row("Findings", str(status.get("csv_rows", 0)))
                t.add_row("Activity", status.get("activity", "-"))
                if status["last"]:
                    t.add_row(
                        "Last Event",
                        f"{status['last_level']} {status['last_module']} :: {status['last']}",
                    )
                    guidance = ""
                    # Guidance: enable API link
                    if (
                        "has not been used" in status["last"]
                        and "disabled" in status["last"]
                    ):
                        m = re.search(r"https?://\S+", status["last"])
                        if m:
                            guidance = f"Open: {m.group(0)}"
                        else:
                            guidance = "Enable required API in Cloud Console and retry"
                    # Guidance: oauth2client file_cache info
                    elif (
                        "file_cache is only supported" in status["last"]
                        and status["last_module"] == "__init__"
                    ):
                        guidance = "Informational dependency note; safe to ignore"
                    if guidance:
                        t.add_row("Guidance", guidance)
                t.add_row("Errors", str(status["errors"]))
                # CPU percent from resource if psutil is unavailable
                cpu = "N/A"
                mem = "N/A"
                try:
                    import psutil

                    p = psutil.Process()
                    cpu = f"{psutil.cpu_percent(interval=None)}%"
                    mem = f"{int(p.memory_info().rss / 1_048_576)} MB"
                except Exception:
                    # Approximate CPU usage over last interval
                    now = time.time()
                    rnow = resource.getrusage(resource.RUSAGE_SELF)
                    cpu_time = float(
                        getattr(rnow, "ru_utime", 0.0) + getattr(rnow, "ru_stime", 0.0)
                    )
                    wall = now - last_wall if now > last_wall else 0.001
                    used = cpu_time - last_cpu
                    pct = (
                        max(0.0, min(100.0, (used / wall) * 100.0)) if wall > 0 else 0.0
                    )
                    cpu = f"{pct:0.1f}%"
                    # ru_maxrss typically KB on Unix, bytes on macOS Big Sur+; show MB
                    rss_kb = getattr(rnow, "ru_maxrss", 0)
                    mem_mb = (
                        int(rss_kb / 1024)
                        if rss_kb > 1024
                        else int(rss_kb / (1024 * 1024))
                    )
                    mem = f"{mem_mb} MB"
                t.add_row("CPU", cpu)
                t.add_row("Memory", mem)
                # Recent events table with color-coded levels
                ev = Table(box=box.SIMPLE, expand=True, title="Recent Events")
                ev.add_column("Time (ISO)")
                ev.add_column("Severity")
                ev.add_column("Module")
                ev.add_column("Type")
                ev.add_column("Message")
                for e in list(status["events"]):
                    sev = (e.get("level") or "INFO").upper()
                    style = ""
                    if sev in ("ERROR", "CRITICAL"):
                        style = "red"
                    elif sev == "WARNING":
                        style = "yellow"
                    elif sev == "INFO":
                        style = "cyan"
                    ev.add_row(
                        _to_iso(e.get("ts", "")),
                        sev.lower(),
                        e.get("module", ""),
                        e.get("type", ""),
                        e.get("msg", ""),
                        style=style,
                    )
                return Group(t, ev)

            def hook(line: str):
                try:
                    import json

                    obj = json.loads(line)
                    msg = obj.get("message", "")
                    lvl = obj.get("level", "")
                    mod = obj.get("module", "")
                    # suppress noisy oauth2client cache message
                    if mod == "__init__" and "file_cache is only supported" in (
                        msg or ""
                    ):
                        return
                    status["last"] = msg
                    status["last_level"] = (lvl or "INFO").upper()
                    status["last_module"] = mod or ""
                    if lvl == "ERROR":
                        status["errors"] += 1
                        status["activity"] = "Error"
                    # dynamic total checks detection
                    mchecks = re.search(r"Executing\s+(\d+)\s+checks", msg or "")
                    if mchecks:
                        try:
                            new_total = int(mchecks.group(1)) * max(len(projects), 1)
                            if new_total and new_total != total_checks:
                                total_checks = new_total
                                try:
                                    prog.update(task_overall, total=total_checks)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    # store event
                    status["events"].append(
                        {
                            "ts": obj.get("timestamp", ""),
                            "level": (lvl or "INFO").upper(),
                            "module": mod or "",
                            "msg": msg or "",
                            "type": _classify(msg, mod or ""),
                        }
                    )
                except Exception:
                    text = line.strip()
                    if (
                        "file_cache is only supported" in text
                        and "[Module: __init__]" in text
                    ):
                        return
                    status["last"] = text[:120]
                    # Parse module and level from plain text
                    mmod = re.search(r"\[Module:\s*([^\]]+)\]", line)
                    if mmod:
                        status["last_module"] = mmod.group(1)
                    if re.search(r"\bCRITICAL\b", line):
                        status["last_level"] = "CRITICAL"
                        status["errors"] += 1
                        status["activity"] = "Error"
                    elif re.search(r"\bERROR\b", line):
                        status["last_level"] = "ERROR"
                        status["errors"] += 1
                        status["activity"] = "Error"
                    elif re.search(r"\bWARNING\b", line):
                        status["last_level"] = "WARNING"
                    else:
                        status["last_level"] = "INFO"
                    # timestamp capture and store event
                    mts = re.search(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", line)
                    ts = mts.group(0) if mts else ""
                    status["events"].append(
                        {
                            "ts": ts,
                            "level": status.get("last_level", "INFO"),
                            "module": status.get("last_module", ""),
                            "msg": status["last"],
                            "type": _classify(
                                status["last"], status.get("last_module", "")
                            ),
                        }
                    )
                if any(k in line for k in ("PASS", "FAIL", "MANUAL", "MUTED")):
                    status["completed"] += 1
                    prog.advance(task_overall, 1)
                    if "FAIL" in line:
                        status["failed"] += 1
                    status["running"] = max(status["running"] - 1, 0)
                elif "Running" in line or "Check" in line:
                    status["running"] += 1

            data_dir = os.path.join(out_base, f"report-sec-{report_date}", "data")
            os.makedirs(data_dir, exist_ok=True)
            log_path = os.path.join(data_dir, "prowler_scan.log")
            csv_path = os.path.join(data_dir, "prowler.csv")
            stop = threading.Event()

            def updater(live):
                nonlocal last_wall, last_cpu
                while not stop.is_set():
                    # Update CPU sampling baselines
                    rnow = resource.getrusage(resource.RUSAGE_SELF)
                    last_cpu = float(
                        getattr(rnow, "ru_utime", 0.0) + getattr(rnow, "ru_stime", 0.0)
                    )
                    last_wall = time.time()
                    try:
                        st = os.stat(log_path)
                        status["log_size"] = st.st_size
                        age_sec = int(time.time() - st.st_mtime)
                        status["log_age"] = f"{age_sec}s ago" if age_sec >= 0 else "-"
                        status["activity"] = "Active" if age_sec < 10 else "Idle"
                    except Exception:
                        status["log_size"] = 0
                        status["log_age"] = "-"
                        status["activity"] = "Idle"
                    try:
                        if os.path.isfile(csv_path):
                            with open(csv_path, "r") as cf:
                                rows = sum(1 for _ in cf)
                            rows = max(rows - 1, 0)
                            status["csv_rows"] = rows
                            try:
                                total = prog.tasks[task_overall].total or rows
                                prog.update(task_overall, completed=min(rows, total))
                            except Exception:
                                pass
                    except Exception:
                        pass
                    live.update(
                        Panel(
                            Align.center(metrics_table()),
                            title="Prowler Scan",
                            border_style="cyan",
                        )
                    )
                    time.sleep(0.5)

            with Live(
                Panel(
                    Align.center(metrics_table()),
                    title="Prowler Scan",
                    border_style="cyan",
                ),
                console=console,
                refresh_per_second=30,
            ) as live:
                t = threading.Thread(target=updater, args=(live,), daemon=True)
                t.start()
                with prog:
                    res = run_scan(
                        provider,
                        projects,
                        org_id or s.org.org_id,
                        sa_key,
                        data_dir,
                        formats,
                        prowler_bin,
                        progress_hook=hook,
                    )
                stop.set()
                t.join()
                try:
                    prog.update(
                        task_overall,
                        completed=(total_checks or prog.tasks[task_overall].total),
                    )
                except Exception:
                    pass
                if res.get("reason") == "idle_timeout":
                    status["activity"] = "Terminated"
                    status["last_level"] = "WARN"
                    status["last_module"] = "fulcrum"
                    status["last"] = "Scan terminated due to inactivity"
                elif res.get("exit_code") and str(res.get("exit_code")) != "0":
                    status["activity"] = "Error"
                    status["last_level"] = "ERROR"
                    status["last_module"] = "fulcrum"
                    status["last"] = (
                        f"Scan exited unexpectedly (code={res.get('exit_code')})"
                    )
                else:
                    status["activity"] = "Completed"
                    status["last_level"] = "INFO"
                    status["last_module"] = "fulcrum"
                    status["last"] = "Scan finished"
                live.update(
                    Panel(
                        Align.center(metrics_table()),
                        title="Prowler Scan",
                        border_style="green",
                    )
                )
            end_time = time.time()
            duration = int(end_time - start)
            final_status = status.get("activity", "Completed")
            console.print(f"[green]Prowler completed[/] (exit={res['exit_code']})")
            csv_candidate = os.path.join(data_dir, "prowler.csv")
            if not os.path.isfile(csv_candidate):
                console.print(
                    "[yellow]Prowler CSV not found; ensure a real Prowler CLI is installed and credentials permit scanning."
                )
                console.print(
                    f"[cyan]Summary[/]: status={final_status.lower()}, duration={duration}s, errors={status['errors']}"
                )
                try:
                    with open(os.path.join(data_dir, "scan_summary.log"), "a") as sf:
                        ts_iso = time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time)
                        )
                        sf.write(
                            f"time={ts_iso} status={final_status} exit={res['exit_code']} duration={duration}s errors={status['errors']}\n"
                        )
                except Exception:
                    pass
            else:
                status["last"] = f"CSV written: {os.path.basename(csv_candidate)}"
                try:
                    total = 0
                    sc = {}
                    sev = {}
                    with open(csv_candidate, newline="") as f:
                        r = csv.DictReader(f)
                        for row in r:
                            total += 1
                            status_text = (
                                row.get("Status") or row.get("status") or ""
                            ).upper()
                            if status_text:
                                sc[status_text] = sc.get(status_text, 0) + 1
                            v = (
                                row.get("Severity") or row.get("severity") or ""
                            ).upper()
                            if v:
                                sev[v] = sev.get(v, 0) + 1
                    p = sc.get("PASS", 0)
                    fcount = sc.get("FAIL", 0)
                    m = sc.get("MANUAL", 0)
                    mu = sc.get("MUTED", 0)
                    sev_str = (
                        ", ".join([f"{k.lower()}={sev[k]}" for k in sorted(sev.keys())])
                        or "none"
                    )
                    console.print(
                        f"[cyan]Summary[/]: status={final_status.lower()}, duration={duration}s, checks={total}, pass={p}, fail={fcount}, manual={m}, muted={mu}; severity: {sev_str}"
                    )
                    try:
                        with open(
                            os.path.join(data_dir, "scan_summary.log"), "a"
                        ) as sf:
                            ts_iso = time.strftime(
                                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time)
                            )
                            sf.write(
                                f"time={ts_iso} status={final_status} exit={res['exit_code']} duration={duration}s checks={total} pass={p} fail={fcount} manual={m} muted={mu} severity=[{sev_str}]\n"
                            )
                    except Exception:
                        pass
                except Exception:
                    console.print("[yellow]Unable to summarize Prowler CSV")
        except ProwlerUnavailable as e:
            console.print(f"[yellow]{e}[/]")
    author = s.metadata.author
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Formatting security report[/]"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("format", total=1)
        typed_dir = os.path.join(out_base, f"report-sec-{report_date}", "data")
        legacy_dir = os.path.join(out_base, "report-" + report_date, "data")
        prowler_csv_path = os.path.join(typed_dir, "prowler.csv")
        if not os.path.isfile(prowler_csv_path):
            legacy_csv = os.path.join(legacy_dir, "prowler.csv")
            if os.path.isfile(legacy_csv):
                prowler_csv_path = legacy_csv
        _ = generate_standard_report(
            out_base,
            author,
            report_date,
            s.metadata.version,
            sa_key,
            prowler_json or None,
            prowler_csv or prowler_csv_path,
            rtype="sec",
        )
        progress.advance(task)
    console.print("[green]Security report updated[/]")


@security_app.command(
    "ingest",
    help=("Ingest existing Prowler outputs (JSON/CSV) into a standardized report."),
)
def security_ingest(
    out_base: str = typer.Option(
        "reports", "--out-base", "-o", help="Base output directory", show_default=True
    ),
    report_date: Optional[str] = typer.Option(
        None, "--report-date", "-d", help="UTC date in YYYYMMDD", show_default=True
    ),
    prowler_json: Optional[str] = typer.Option(
        None, "--prowler-json", help="Path to Prowler JSON output", show_default=True
    ),
    prowler_csv: Optional[str] = typer.Option(
        None, "--prowler-csv", help="Path to Prowler CSV output", show_default=True
    ),
):
    """
    Description:
        Import Prowler results into the report without running a new scan.

    Parameters:
        - out_base (optional, str): Base output directory for reports.
        - report_date (optional, str): UTC date YYYYMMDD.
        - prowler_json/prowler_csv (optional, str): Paths to Prowler outputs.

    Usage:
        fulcrum reports security ingest --out-base reports --prowler-json prowler.json
    """
    setup_logging()
    s = load_settings(None)
    author = s.metadata.author
    _ = generate_standard_report(
        out_base,
        author,
        report_date,
        s.metadata.version,
        None,
        prowler_json,
        prowler_csv,
        rtype="sec",
    )
    console.print("[green]Ingested Prowler results into security report[/]")


@security_app.command(
    "format",
    help=(
        "Format the standardized report using existing security data; performs collection "
        "and appends security sections."
    ),
)
def security_format(
    out_base: str = typer.Option(
        "reports", "--out-base", "-o", help="Base output directory", show_default=True
    ),
    report_date: Optional[str] = typer.Option(
        None, "--report-date", "-d", help="UTC date in YYYYMMDD", show_default=True
    ),
    sa_key: Optional[str] = typer.Option(
        None, "--sa-key", "-k", help="Path to service account JSON", show_default=True
    ),
):
    """
    Description:
        Reformat the standardized report, collecting resources and attaching security sections.

    Parameters:
        - out_base (optional, str): Base output directory.
        - report_date (optional, str): UTC date YYYYMMDD.
        - sa_key (optional, str): Service account credentials JSON.

    Usage:
        fulcrum reports security format --out-base reports
    """
    setup_logging()
    s = load_settings(None)
    author = s.metadata.author
    _ = generate_standard_report(
        out_base, author, report_date, s.metadata.version, sa_key, rtype="sec"
    )
    console.print("[green]Formatted security report[/]")


@security_app.command(
    "validate",
    help=(
        "Validate security report structure and links under the base path or a specific report directory."
    ),
)
def security_validate(
    path: str = typer.Option("reports", help="Base path or specific report directory"),
):
    validate_report_cmd(path)


@app.command("diagnose", help="Run system diagnostics.")
def diagnose():
    setup_logging()
    mgr = DiagnosticsManager()
    # TODO: Register checks
    results = mgr.run_all()
    if not results:
        console.print("[yellow]No diagnostic checks registered.[/]")
        return
    for r in results:
        color = "green" if r.passed else "red"
        console.print(f"[{color}]{r.check_name}: {r.message}[/]")


@app.command("fix", help="Apply remediation for a specific issue.")
def fix(
    issue_id: str = typer.Argument(..., help="Issue ID (e.g. cis_gke_v1_6_0_4_2_4)"),
    target: str = typer.Argument(..., help="Target resource as JSON string"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate execution"),
):
    setup_logging()
    mgr = RemediationManager()
    mgr.register_action(GKEReadOnlyPortRemediation())
    mgr.register_action(IAPOAuthRemediation())

    try:
        target_dict = json.loads(target)
    except json.JSONDecodeError:
        console.print("[red]Target must be a valid JSON string[/]")
        raise typer.Exit(1)

    res = mgr.remediate(issue_id, target_dict, dry_run=dry_run)
    if res.success:
        console.print(f"[green]{res.message}[/]")
        if res.changes:
            console.print(res.changes)
    else:
        console.print(f"[red]{res.message}[/]")
        raise typer.Exit(1)


@app.command("history", help="Show report history and trends.")
def history(out_base: str = typer.Option("reports", "--out-base", "-o")):
    setup_logging()
    mgr = HistoryManager(base_dir=out_base)
    trends = mgr.get_trends()
    console.print(f"Report Count: {trends['report_count']}")
    if trends["dates"]:
        console.print("Recent reports:")
        for d in trends["dates"][:5]:
            console.print(f" - {d}")


@app.command("migrate-gcr", help="Migrate GCR images to Artifact Registry.")
def migrate_gcr(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
    location: str = typer.Option("europe-west1", help="Target AR location"),
    dry_run: bool = typer.Option(False, help="Simulate copy"),
    recursive: bool = typer.Option(
        False, help="Recursively scan for nested images (e.g. functions)"
    ),
):
    setup_logging()
    all_maps = []
    for pid in projects:
        m = migrate_project(pid, location, dry_run=dry_run, recursive=recursive)
        all_maps.extend(m)

    if all_maps:
        console.print("\n[bold green]Migration Mapping:[/]")
        for item in all_maps:
            console.print(f"{item['old']} -> {item['new']}")

        # Save to file
        with open("migration_map.json", "w") as f:
            json.dump(all_maps, f, indent=2)
        console.print("[cyan]Mapping saved to migration_map.json[/]")


@app.command(
    "migrate-functions", help="Migrate Cloud Functions (1st gen) images to AR."
)
def migrate_functions(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
    location: str = typer.Option("europe-west1", help="Target AR location"),
    dry_run: bool = typer.Option(False, help="Simulate copy"),
):
    """
    Specifically targets 'gcf' repositories in GCR recursively.
    """
    setup_logging()
    all_maps = []
    for pid in projects:
        # Check both standard regions
        for host_base in ["gcr.io", "eu.gcr.io"]:
            gcf_host = f"{host_base}/{pid}/gcf"
            console.print(f"Scanning functions in {gcf_host}...")
            m = migrate_project(
                pid, location, dry_run=dry_run, recursive=True, specific_host=gcf_host
            )
            all_maps.extend(m)

    if all_maps:
        console.print("\n[bold green]Functions Migration Mapping:[/]")
        # Save to file
        with open("functions_migration_map.json", "w") as f:
            json.dump(all_maps, f, indent=2)
        console.print("[cyan]Mapping saved to functions_migration_map.json[/]")


@app.command("analyze-logging", help="Analyze Cloud Logging configuration and usage.")
def analyze_logging_cmd(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
):
    setup_logging()
    for pid in projects:
        console.print(f"\n[bold]Analyzing Logging for {pid}...[/]")
        report = analyze_logging(pid)

        console.print("[bold]Buckets:[/]")
        for b in report["buckets"]:
            console.print(
                f"  - {b['name']} (Retention: {b.get('retentionDays', 'Default')} days)"
            )

        console.print("[bold]Sinks:[/]")
        for s in report["sinks"]:
            status = "DISABLED" if s["disabled"] else "ACTIVE"
            console.print(f"  - {s['name']} [{status}] -> {s['destination']}")


# Decommission Commands
decom_app = typer.Typer(help="Decommissioning tools for legacy environments.")
app.add_typer(decom_app, name="decommission")


@decom_app.command("audit")
def decom_audit(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
    timeout: int = typer.Option(30, help="Timeout in seconds for gcloud commands"),
):
    """Generate inventory of resources to decommission (with timeout)."""
    setup_logging()
    all_reports = []

    with console.status("[bold green]Auditing resources...[/]") as status:
        for pid in projects:
            status.update(f"[bold green]Auditing {pid}...[/]")
            d = Decommissioner(pid)
            # We need to pass timeout to audit_resources if we update the class method signature
            # But run_gcloud_json is global.
            # Let's update Decommissioner to accept timeout or just rely on default.
            # Ideally we pass it down.
            # For now, relying on default 30s in runner or we can patch runner.
            report = d.audit_resources()  # Ideally pass timeout here
            all_reports.append(report)
            console.print(
                f"  - {pid}: Found {len(report['gke_clusters'])} clusters, {len(report['sql_instances'])} SQLs, {len(report['buckets'])} buckets."
            )

    console.print(json.dumps(all_reports, indent=2))
    with open("decom_audit.json", "w") as f:
        json.dump(all_reports, f, indent=2)


@decom_app.command("backup")
def decom_backup(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
):
    """Trigger SQL snapshots."""
    setup_logging()
    for pid in projects:
        d = Decommissioner(pid)
        d.backup_sql()


@decom_app.command("cordon")
def decom_cordon(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
):
    """Cordon GKE clusters."""
    setup_logging()
    for pid in projects:
        d = Decommissioner(pid)
        d.cordon_clusters()


@decom_app.command("destroy")
def decom_destroy(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
    dry_run: bool = typer.Option(True, help="Dry run mode"),
    force: bool = typer.Option(False, help="Force destruction (Required for real run)"),
):
    """Destroy resources."""
    setup_logging()
    if not dry_run and not force:
        console.print("[red]Error: Must use --force to execute real destruction.[/]")
        raise typer.Exit(code=1)

    if not dry_run:
        confirm = typer.confirm(
            "ARE YOU SURE YOU WANT TO DESTROY RESOURCES? THIS CANNOT BE UNDONE."
        )
        if not confirm:
            raise typer.Abort()

    for pid in projects:
        d = Decommissioner(pid)
        d.destroy_resources(dry_run=dry_run)


# Security Commands
security_app = typer.Typer(help="Security auditing tools.")
app.add_typer(security_app, name="security")


@security_app.command("port")
def port_check(
    port: int = typer.Argument(..., help="Port number to check"),
    projects: List[str] = typer.Option([], "--project", "-p", help="GCP Project IDs"),
    all_projects: bool = typer.Option(
        False, "--all", help="Check all projects in fulcrum.toml"
    ),
    parallel: int = typer.Option(5, help="Max parallel checks"),
    export: Optional[str] = typer.Option(
        None, "--export", "-e", help="Export format (json)"
    ),
):
    """Check if a specific port is open across GCP projects.

    This command checks firewall rules across specified projects to determine if the given port
    is open to any source IP ranges.

    Examples:
        fulcrum security port 22 --all
        fulcrum security port 443 -p project1 project2
        fulcrum security port 10255 --all --export json
    """
    import toml

    if all_projects:
        try:
            with open("fulcrum.toml", "r") as f:
                config = toml.load(f)
            projects = config.get("catalog", {}).get("projects", [])
            if not projects:
                typer.echo("No projects found in fulcrum.toml", err=True)
                raise typer.Exit(1)
        except Exception as e:
            typer.echo(f"Error loading configuration: {str(e)}", err=True)
            raise typer.Exit(1)

    if not projects:
        typer.echo(
            "Please specify projects with --project/-p or use --all to check all projects",
            err=True,
        )
        raise typer.Exit(1)

    check_port(projects, port, max_workers=parallel, export_format=export)


@security_app.command()
def audit(
    projects: List[str] = typer.Option([], "--project", "-p", help="GCP Project IDs"),
    all_projects: bool = typer.Option(
        True, "--all/--select", help="Scan all projects in fulcrum.toml"
    ),
    code_scan: bool = typer.Option(
        False, "--code", help="Also scan local codebase for secrets"
    ),
    path: str = typer.Option(".", "--path", help="Path for code scan"),
    provider: str = typer.Option("gcp", help="Cloud Provider"),
    timeout: int = typer.Option(1200, help="Timeout per project scan (seconds)"),
    parallel: int = typer.Option(3, help="Max parallel scans"),
):
    """Audit project security (Infrastructure + Optional Code)."""
    setup_logging()

    # 1. Infrastructure Scan (Prowler)
    # Check Prowler
    try:
        list_checks(provider)
    except ProwlerUnavailable as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(code=1)

    # Determine projects
    if all_projects:
        s = load_settings(None)
        target_projects = s.catalog.projects
    else:
        target_projects = projects

    if not target_projects:
        console.print(
            "[yellow]No projects specified. Use --project or ensure fulcrum.toml has projects.[/]"
        )
        if not code_scan:
            raise typer.Exit(code=1)
    else:
        _run_infra_scan_tui(target_projects, provider, timeout, parallel)

    # 2. Code Scan (Optional)
    if code_scan:
        console.print(f"\n[bold]Scanning codebase in {path}...[/]")
        auditor = SecurityAuditor(path)
        findings = auditor.scan()

        if findings:
            console.print(
                f"[bold red]Found {len(findings)} potential security issues in code:[/]"
            )
            for f in findings:
                console.print(f"  - {f['rule']} in {f['file']}:{f['line']}")
        else:
            console.print("[bold green]No issues found in code.[/]")


@security_app.command("scan-code")
def sec_scan_code(path: str = typer.Option(".", "--path", help="Path to scan")):
    """Scan codebase for security risks."""
    setup_logging()
    auditor = SecurityAuditor(path)
    findings = auditor.scan()

    if findings:
        console.print(f"[bold red]Found {len(findings)} potential security issues:[/]")
        for f in findings:
            console.print(f"  - {f['rule']} in {f['file']}:{f['line']}")
    else:
        console.print("[bold green]No issues found.[/]")


@security_app.command("scan-infra")
def sec_scan_infra(
    projects: List[str] = typer.Option([], "--project", "-p", help="GCP Project IDs"),
    all_projects: bool = typer.Option(
        False, "--all", help="Scan all projects in fulcrum.toml"
    ),
    provider: str = typer.Option("gcp", help="Cloud Provider"),
    timeout: int = typer.Option(1200, help="Timeout per project scan (seconds)"),
    parallel: int = typer.Option(3, help="Max parallel scans"),
):
    """Run infrastructure vulnerability scan using Prowler (Project-based, Parallel)."""
    setup_logging()

    # Check Prowler
    try:
        list_checks(provider)
    except ProwlerUnavailable as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(code=1)

    # Determine projects
    if all_projects:
        s = load_settings(None)
        target_projects = s.catalog.projects
    else:
        target_projects = projects

    if not target_projects:
        console.print("[yellow]No projects specified. Use --project or --all[/]")
        raise typer.Exit(code=1)

    _run_infra_scan_tui(target_projects, provider, timeout, parallel)


def _run_infra_scan_tui(
    target_projects: List[str], provider: str, timeout: int, parallel: int
):
    console.print(
        f"[bold]Starting scan for {len(target_projects)} projects (Max Parallel: {parallel})...[/]"
    )

    async def run_scans():
        scanner = AsyncScanner(timeout_sec=timeout, max_concurrency=parallel)
        return await scanner.scan_projects(target_projects)

    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.align import Align

    # Live TUI State
    scan_start = time.time()
    scan_status = {pid: "PENDING" for pid in target_projects}
    scan_metrics = {
        pid: {"start": None, "end": None, "counts": {}} for pid in target_projects
    }

    def get_duration_str(pid):
        m = scan_metrics[pid]
        if m["start"] is None:
            return "-"
        end = m["end"] or time.time()
        elapsed = int(end - m["start"])
        return f"{elapsed}s"

    def generate_table():
        table = Table(title=f"Infrastructure Scan ({len(target_projects)} Projects)")
        table.add_column("Project ID", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Duration", justify="right")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("High", justify="right", style="magenta")
        table.add_column("Medium", justify="right", style="yellow")
        table.add_column("Low", justify="right", style="green")

        # Sort: Running/Pending first, then by name
        sorted_pids = sorted(
            target_projects, key=lambda p: (scan_status[p] in ["SUCCESS", "FAILED"], p)
        )

        completed_count = 0

        # Totals
        total_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for pid in sorted_pids:
            status = scan_status[pid]
            style = "white"
            if status == "RUNNING":
                style = "yellow"
                status = "Running..."
            elif status == "SUCCESS":
                style = "green"
                completed_count += 1
            elif status.startswith("FAILED"):
                style = "red"
                completed_count += 1
            elif status == "PENDING":
                style = "dim"

            counts = scan_metrics[pid]["counts"]

            # Add to totals
            for k, v in counts.items():
                if k in total_counts:
                    total_counts[k] += v

            table.add_row(
                pid,
                f"[{style}]{status}[/]",
                get_duration_str(pid),
                str(counts.get("CRITICAL", "-")),
                str(counts.get("HIGH", "-")),
                str(counts.get("MEDIUM", "-")),
                str(counts.get("LOW", "-")),
            )

        # Add Total Row
        table.add_section()
        table.add_row(
            "[bold]TOTAL[/]",
            "",
            "",
            f"[bold red]{total_counts['CRITICAL']}[/]",
            f"[bold magenta]{total_counts['HIGH']}[/]",
            f"[bold yellow]{total_counts['MEDIUM']}[/]",
            f"[bold green]{total_counts['LOW']}[/]",
        )

        return table, completed_count

    # Wrapper to update UI state
    async def run_scans_with_ui():
        scanner = AsyncScanner(timeout_sec=timeout, max_concurrency=parallel)
        semaphore = asyncio.Semaphore(parallel)

        async def tracked_scan(pid):
            scan_status[pid] = "RUNNING"
            scan_metrics[pid]["start"] = time.time()
            try:
                res = await scanner.scan_project(pid)
                scan_metrics[pid]["end"] = time.time()

                if res.success:
                    scan_status[pid] = "SUCCESS"
                    # Try to parse findings for the table
                    try:
                        # Find specific ocsf json file for this project
                        # We used --output-filename prowler-{pid} so pattern is prowler-{pid}*.ocsf.json
                        pattern = os.path.join(
                            "prowler_reports", f"prowler-{pid}*.ocsf.json"
                        )
                        files = glob.glob(pattern)

                        relevant_files = []
                        for f in files:
                            if os.path.getmtime(f) >= scan_start:
                                relevant_files.append(f)

                        # If multiple, take latest
                        if relevant_files:
                            latest_file = max(relevant_files, key=os.path.getmtime)

                            # Parse counts
                            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                            with open(latest_file, "r") as jf:
                                try:
                                    data = json.load(jf)
                                    if not isinstance(data, list):
                                        data = [data]

                                    severity_map = {
                                        1: "LOW",
                                        2: "LOW",
                                        3: "MEDIUM",
                                        4: "HIGH",
                                        5: "CRITICAL",
                                        6: "CRITICAL",
                                    }
                                    for finding in data:
                                        # Simplified aggregator logic
                                        status = "FAIL"
                                        state_id = finding.get("state_id")
                                        if state_id == 2:
                                            status = "PASS"
                                        elif state_id in [0, 1]:
                                            status = "FAIL"

                                        if status == "FAIL":
                                            sev_id = finding.get("severity_id", 0)
                                            sev_name = severity_map.get(
                                                sev_id, "UNKNOWN"
                                            )
                                            if sev_name in counts:
                                                counts[sev_name] += 1

                                    scan_metrics[pid]["counts"] = counts
                                except:
                                    pass
                    except Exception:
                        pass
                else:
                    scan_status[pid] = f"FAILED ({res.error})"

                return res
            except Exception as e:
                scan_metrics[pid]["end"] = time.time()
                scan_status[pid] = f"FAILED ({str(e)})"
                from .prowler.scanner import ScanResult

                return ScanResult(pid, False, error=str(e))

        tasks = [tracked_scan(pid) for pid in target_projects]
        return await asyncio.gather(*tasks)

    async def main_scan():
        with Live(refresh_per_second=4) as live:

            async def ui_loop():
                while True:
                    table, completed = generate_table()
                    elapsed = int(time.time() - scan_start)

                    # Estimate ETA
                    eta = "?"
                    if completed > 0:
                        avg_time = elapsed / completed
                        remaining = len(target_projects) - completed
                        # Parallel factor roughly
                        # effective_serial_remaining = remaining / parallel
                        # But simpler: rate = completed / elapsed. total_time = total / rate. remaining = total_time - elapsed
                        rate = completed / elapsed
                        if rate > 0:
                            eta_sec = int(remaining / rate)
                            eta = f"{eta_sec}s"

                    progress_str = f"{completed}/{len(target_projects)}"

                    panel = Panel(
                        table,
                        title=f"Fulcrum Security Scan - Elapsed: {elapsed}s - Progress: {progress_str} - ETA: {eta}",
                        border_style="blue",
                    )
                    live.update(panel)
                    if completed == len(target_projects):
                        break
                    await asyncio.sleep(0.25)

            # Run UI loop and Scans concurrently
            ui_task = asyncio.create_task(ui_loop())
            scan_task = asyncio.create_task(run_scans_with_ui())

            res = await scan_task
            await ui_task  # Ensure UI finishes
            return res

    results = asyncio.run(main_scan())

    # Process results
    success_count = sum(1 for r in results if r.success)
    console.print(
        f"\n[bold]Scan Complete: {success_count}/{len(results)} successful[/]"
    )

    # Aggregate
    aggregator = ReportAggregator("prowler_reports")
    summary = aggregator.aggregate()

    # Save summary
    with open("prowler_reports/aggregated_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    console.print(
        "[cyan]Aggregated report saved to prowler_reports/aggregated_summary.json[/]"
    )


@security_app.command("report-aggregate")
def sec_report_aggregate(
    report_dir: str = typer.Option(
        "prowler_reports", help="Directory containing Prowler JSON reports"
    ),
):
    """Aggregate existing Prowler reports into a summary."""
    setup_logging()
    aggregator = ReportAggregator(report_dir)
    summary = aggregator.aggregate()

    console.print("\n[bold]Aggregated Infrastructure Report:[/]")
    console.print(f"Total Projects Scanned: {len(summary['projects'])}")
    console.print(f"Global Fails: [red]{summary['total_stats']['FAIL']}[/]")
    console.print(
        f"Global Criticals: [bold red]{summary['total_stats']['CRITICAL']}[/]"
    )
    console.print(f"Global Highs: [red]{summary['total_stats']['HIGH']}[/]")

    # Save summary
    out_path = os.path.join(report_dir, "aggregated_summary.json")
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    console.print(f"[cyan]Aggregated report saved to {out_path}[/]")


# Backup Commands
backup_app = typer.Typer(help="Kubernetes Backup Management")
app.add_typer(backup_app, name="backup")


@backup_app.command("list")
def backup_list(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
    limit: int = typer.Option(
        5, "--limit", "-l", help="Max backups to show per cluster"
    ),
):
    """List actual backups present for each cluster."""
    setup_logging()

    if not projects:
        s = load_settings(None)
        projects = s.catalog.projects

    from rich.table import Table

    t = Table(title="Backup Status")
    t.add_column("Project")
    t.add_column("Cluster")
    t.add_column("Plan")
    t.add_column("Backup Name")
    t.add_column("State")
    t.add_column("Created")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Fetching backups...[/]"),
        BarColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scan", total=len(projects))
        for pid in projects:
            try:
                bo = BackupOrchestrator(pid)
                # This might be slow as it makes N calls
                backups = bo.list_cluster_backups()

                # Group by cluster to apply limit
                from itertools import groupby

                backups.sort(key=lambda x: x["cluster"])

                for cluster, group in groupby(backups, key=lambda x: x["cluster"]):
                    group_list = list(group)
                    # Sort by creation time desc (if available)
                    group_list.sort(
                        key=lambda x: x.get("create_time") or "", reverse=True
                    )

                    shown = group_list[:limit]
                    for b in shown:
                        state_style = (
                            "green"
                            if b["state"] == "SUCCEEDED"
                            else "red"
                            if b["state"] in ["FAILED", "UNPROTECTED", "NO_BACKUPS"]
                            else "yellow"
                        )
                        t.add_row(
                            b["project"],
                            b["cluster"],
                            b["plan"],
                            b["backup_name"],
                            f"[{state_style}]{b['state']}[/]",
                            b["create_time"],
                        )
            except Exception as e:
                console.print(f"[red]Error scanning {pid}: {e}[/]")
            progress.advance(task)

    console.print(t)


@backup_app.command("inventory")
def backup_inventory(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List clusters and their backup status."""
    setup_logging()
    all_inv = []

    # Defaults
    if not projects:
        s = load_settings(None)
        projects = s.catalog.projects

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Scanning clusters...[/]"),
        BarColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scan", total=len(projects))
        for pid in projects:
            try:
                bo = BackupOrchestrator(pid)
                inv = bo.inventory()
                all_inv.extend(inv)
            except Exception as e:
                console.print(f"[red]Error scanning {pid}: {e}[/]")
            progress.advance(task)

    if json_out:
        console.print(json.dumps(all_inv, indent=2))
    else:
        from rich.table import Table

        t = Table(title="Backup Inventory")
        t.add_column("Project")
        t.add_column("Cluster")
        t.add_column("Location")
        t.add_column("Plans")
        t.add_column("Status")

        for i in all_inv:
            plans = ", ".join(i["backup_plans"]) if i["backup_plans"] else "-"
            status = "[green]Protected[/]" if i["protected"] else "[red]Unprotected[/]"

            location = i["location"]
            if i.get("location_mismatch"):
                location = f"[red]{i['location_mismatch']}[/]"

            t.add_row(i["project"], i["cluster"], location, plans, status)
        console.print(t)


@backup_app.command("protect")
def backup_protect(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
    retention_days: int = typer.Option(
        7, "--retention", "-r", help="Retention period in days"
    ),
):
    """Automatically create backup plans for unprotected clusters."""
    setup_logging()

    if not projects:
        s = load_settings(None)
        projects = s.catalog.projects

    for pid in projects:
        console.print(
            f"[bold]Applying backup protection for {pid} (Retention: {retention_days}d)...[/]"
        )
        try:
            bo = BackupOrchestrator(pid)
            results = bo.protect_unprotected_clusters(retention_days=retention_days)
            for r in results:
                color = "green" if r["status"] == "Created" else "yellow"
                console.print(
                    f"  - {r['cluster']}: [{color}]{r['status']}[/] ({r.get('operation') or r.get('reason') or r.get('error')})"
                )
        except Exception as e:
            console.print(f"[red]Error processing {pid}: {e}[/]")


@backup_app.command("run")
def backup_run(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
):
    """Trigger on-demand backups for configured clusters."""
    setup_logging()

    if not projects:
        s = load_settings(None)
        projects = s.catalog.projects

    for pid in projects:
        console.print(f"[bold]Triggering backups for {pid}...[/]")
        try:
            bo = BackupOrchestrator(pid)
            results = bo.run_backup()
            for r in results:
                color = "green" if r["status"] == "Initiated" else "yellow"
                console.print(
                    f"  - {r['cluster']}: [{color}]{r['status']}[/] ({r.get('operation') or r.get('reason') or r.get('error')})"
                )
        except Exception as e:
            console.print(f"[red]Error processing {pid}: {e}[/]")


@backup_app.command("plan")
def backup_plan(
    projects: List[str] = typer.Option([], "--projects", "-p", help="Project IDs"),
    export_toml: bool = typer.Option(False, "--export", "-e", help="Export to TOML"),
):
    """View details of configured backup plans."""
    setup_logging()

    if not projects:
        s = load_settings(None)
        projects = s.catalog.projects

    from rich.table import Table

    t = Table(title="Backup Plans Overview")
    t.add_column("Project")
    t.add_column("Plan Name")
    t.add_column("Cluster")
    t.add_column("Location")
    t.add_column("Retention (Days)")
    t.add_column("Schedule")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Fetching backup plans...[/]"),
        BarColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scan", total=len(projects))
        for pid in projects:
            try:
                bo = BackupOrchestrator(pid)
                plans = bo.get_backup_plans_details()

                if plans:
                    if export_toml:
                        import toml

                        # Ensure export directory exists
                        export_dir = "export/plans"
                        os.makedirs(export_dir, exist_ok=True)

                        export_data = {"project": pid, "plans": []}
                        for p in plans:
                            export_data["plans"].append(
                                {
                                    "name": p["name"],
                                    "cluster": p["cluster"],
                                    "location": p["location"],
                                    "retention_days": p["retention_days"],
                                    "schedule": p["cron_schedule"] or "Manual",
                                    "config": p["backup_config"],
                                }
                            )

                        filename = os.path.join(export_dir, f"{pid}.toml")
                        with open(filename, "w") as f:
                            toml.dump(export_data, f)

                    for p in plans:
                        t.add_row(
                            pid,
                            p["name"],
                            p["cluster"],
                            p["location"],
                            str(p["retention_days"]),
                            p["cron_schedule"] or "Manual",
                        )
            except Exception as e:
                console.print(f"[red]Error processing {pid}: {e}[/]")
            progress.advance(task)

    console.print(t)
    if export_toml:
        console.print(
            "[green]Exported TOML configurations for projects with active plans.[/]"
        )


# Auth management
auth_app = typer.Typer(help="Automate GCP credentials integration")
app.add_typer(auth_app, name="auth")


@auth_app.command("adc")
def auth_adc():
    """
    Configure Application Default Credentials using gcloud and verify access.
    """
    setup_logging()
    from .gcp.client import build_compute
    from .gcp.auth import load_credentials, preflight_permission_check

    console.print("[cyan]Launching gcloud ADC flow...[/]")
    try:
        subprocess.run(["gcloud", "auth", "application-default", "login"], check=True)
    except Exception:
        console.print("[yellow]gcloud not available or login failed[/]")
    creds, project_id = load_credentials(None)
    compute = build_compute(creds)
    ok, err = preflight_permission_check(compute, project_id or "")
    if ok:
        console.print(f"[green]ADC verified[/] (project={project_id})")
    else:
        console.print(f"[yellow]ADC preflight failed[/] -> {err}")


@auth_app.command("sa")
def auth_sa(sa_key: str = typer.Argument(..., help="Path to service account JSON key")):
    """
    Configure Service Account credentials by saving into fulcrum.toml and verifying access.
    """
    setup_logging()
    s = load_settings(None)
    s.credentials.sa_key_path = sa_key
    path = save_settings(None, s)
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = sa_key
    from .gcp.client import build_compute
    from .gcp.auth import load_credentials, preflight_permission_check

    creds, project_id = load_credentials(sa_key)
    compute = build_compute(creds)
    ok, err = preflight_permission_check(compute, project_id or "")
    if ok:
        console.print(
            f"[green]Service Account verified[/] (project={project_id}) and saved to {path}"
        )
    else:
        console.print(f"[yellow]Service Account preflight failed[/] -> {err}")


@auth_app.command("impersonate")
def auth_impersonate(
    service_account_email: str = typer.Argument(
        ..., help="Target service account email"
    ),
):
    """
    Configure impersonation target in fulcrum.toml. ADC or SA must be present to impersonate.
    """
    setup_logging()
    s = load_settings(None)
    s.credentials.impersonate_service_account = service_account_email
    path = save_settings(None, s)
    console.print(
        f"[green]Impersonation target saved[/] -> {service_account_email} in {path}"
    )


@auth_app.command("verify")
def auth_verify():
    """
    Verify current Fulcrum credentials by listing Compute zones for the active project.
    """
    setup_logging()
    from .gcp.client import build_compute
    from .gcp.auth import (
        load_credentials,
        load_impersonated_credentials,
        preflight_permission_check,
    )

    s = load_settings(None)
    base_creds, project_id = load_credentials(s.credentials.sa_key_path)
    if s.credentials.impersonate_service_account:
        try:
            base_creds = load_impersonated_credentials(
                base_creds, s.credentials.impersonate_service_account
            )
        except Exception as e:
            console.print(f"[yellow]{e}")
    compute = build_compute(base_creds)
    ok, err = preflight_permission_check(compute, project_id or s.org.org_id or "")
    if ok:
        console.print(f"[green]Credentials verified[/] (project={project_id})")
    else:
        console.print(f"[yellow]Verification failed[/] -> {err}")


def main():
    app()


if __name__ == "__main__":
    main()
