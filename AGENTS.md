# Fulcrum - GCP Catalog CLI

**Generated:** 2026-01-15 08:36
**Language:** Python 3.13+ | **Package:** uv | **Type:** CLI+TUI

## Overview

Executive GCP catalog CLI with rich TUI. Collects GCP assets, generates reports (Markdown/CSV/IAM matrix), integrates Prowler security scans.

## Structure

```
./
├── src/
│   ├── cli.py                    # Typer entry point
│   ├── commands/                 # Subcommands: config, docs, report, security
│   ├── core/                     # Business logic (catalog, reporting, validation)
│   ├── gcp/                      # GCP API clients & remediation
│   ├── prowler/                  # Prowler integration & normalization
│   ├── security/                 # Security auditing
│   ├── ui/                       # Textual TUI dashboard
│   └── templates/                # Jinja2 report templates
├── tests/                        # 22 test files
├── docs/fulcrum/                 # Command documentation
└── fulcrum.toml                  # Runtime config
```

## Where to Look

| Task | Location | Notes |
|------|----------|-------|
| CLI entry | `src/cli.py` | Typer app with subcommands |
| Report generation | `src/core/report_builder.py` | Strategy pattern (std/executive) |
| GCP discovery | `src/gcp/*.py` | 13 modules for asset collection |
| Prowler integration | `src/prowler/*.py` | Parse, normalize, aggregate findings |
| TUI dashboard | `src/ui/app.py` | Textual with async workers |
| Config mgmt | `src/commands/config.py` | TOML config via `fulcrum config` |

## Code Map

| Module | Classes/Functions | Purpose |
|--------|-------------------|---------|
| `core/report_builder.py` | `ReportStrategy`, `ReportBuilder`, `ReportConfig`, `ReportResult` | Unified report architecture |
| `core/catalog.py` | `run_orchestrator`, `validate_csvs` | Catalog validation |
| `prowler/models.py` | `CanonicalFinding`, `Severity`, `Framework` | Pydantic security models |
| `gcp/client.py` | `build_compute`, `list_instances`, `list_firewalls` | GCP API builders |
| `ui/app.py` | `DataStore`, `ViewState`, `TableData` | Reactive TUI state |
| `security/audit.py` | `ScanProgress`, security regex patterns | Async security scanner |

## Conventions

- **Python 3.13+**: Type hints required, mypy strict mode
- **Logging**: `structlog` for structured JSON logs
- **CLI**: Typer with subcommands; tests use `TyperRunner`
- **Models**: Pydantic v2 with `Field`, `ConfigDict`, enums
- **Reports**: Strategy pattern (`ReportStrategy` ABC)
- **Async**: `asyncio` + `async def` / `await` for I/O
- **TUI**: Textual with reactive `DataStore` and view states
- **Config**: TOML via `tomlkit`; fallback chain: arg → local → XDG → ~/.config

## Anti-Patterns (THIS PROJECT)

- **NO** `print()` for output—use `log.info()` or `rich.Console`
- **NO** blocking I/O in TUI—use async workers
- **NO** raw `dict` access on models—use Pydantic field access
- **NO** secrets in code—use `fulcrum.toml` or env vars

## Commands

```bash
# Development
uv run python -m fulcrum --help           # CLI help
uv run python -m fulcrum report --org-id <ID> --projects p1 p2  # Generate catalog
uv run python -m fulcrum validate --out-dir master-report  # Validate CSV outputs
uv run python -m fulcrum dashboard --out-dir master-report  # Launch TUI
uv run python -m fulcrum config init --config ./fulcrum.toml

# Testing
uv pytest tests/ -q
uv mypy src/
uv ruff check src/
```

## Architecture Notes

- **Catalog Flow**: GCP assets → CSV files → ReportBuilder → Markdown/HTML/CSV
- **Prowler Flow**: Scan → JSON/CSV → Parser → Normalizer → CanonicalFinding → Report
- **TUI State**: `DataStore` reactive with 5-min cache TTL per view
- **Remediation**: GCP-specific modules (`iap_remediation.py`, `logging_quota.py`)
