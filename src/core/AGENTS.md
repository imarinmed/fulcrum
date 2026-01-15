# Core Module - Business Logic

16 modules for catalog, reporting, validation, and templating.

## Overview

Central business logic layer. Handles report generation, data validation, and orchestrates GCP asset collection into consumable outputs.

## Structure

```
src/core/
├── report_builder.py      # Strategy pattern for report generation (KEY)
├── catalog.py             # Orchestrator & CSV validation
├── reporting.py           # Standard report generation
├── validator.py           # Report validation
├── config.py              # Config loading from TOML
├── settings.py            # CLI defaults & settings
├── logging.py             # Structlog setup
├── templates.py           # Jinja2 template loader
├── docs.py                # Executive documentation generation
├── markdown.py            # Markdown utilities
├── remediation.py         # Remediation plan generation
├── collect.py             # Asset collection orchestrator
├── progress.py            # Progress tracking
├── backup.py              # Backup utilities
├── diagnostics.py         # Diagnostic utilities
└── __init__.py            # Module exports
```

## Where to Look

| Task | File | Notes |
|------|------|-------|
| Report generation | `report_builder.py` | **Start here** - contains `ReportBuilder` + strategies |
| Catalog validation | `catalog.py` | `validate_csvs()`, `run_orchestrator()` |
| Config management | `config.py` | TOML loading via `tomlkit` |
| Settings/fallbacks | `settings.py` | `get_cli_defaults()`, `load_settings()` |

## Key Classes

| Class/Function | Purpose |
|----------------|---------|
| `ReportStrategy` | ABC for std/executive report strategies |
| `StandardReportStrategy` | Standard GCP catalog format |
| `ExecutiveReportStrategy` | Executive documentation format |
| `ReportBuilder` | Unified builder with `generate()` |
| `ReportConfig` | Dataclass config (output_dir, report_type, author, etc.) |
| `ReportResult` | Dataclass result (output paths, metadata) |
| `validate_csvs()` | Validates required CSV files exist with correct headers |

## Conventions

- **Strategy Pattern**: Use `ReportStrategy` ABC for new report types
- **Pydantic**: Models in `report_builder.py` use v2 features (`ConfigDict`)
- **Logging**: Use `structlog.get_logger()` for all log calls
- **Paths**: Use `Path` from `pathlib`, avoid string concatenation

## Anti-Patterns

- **NO** hardcoded paths—use `ReportConfig.output_dir`
- **NO** direct `open()` without context manager
- **NO** raw exceptions—use structured logging

## Exports (from `__init__.py`)

```python
from .catalog import run_orchestrator, safe_copy_file, safe_copy_dir, validate_csvs
from .report_builder import ReportBuilder, ReportConfig, ReportResult
from .reporting import generate_standard_report
from .settings import get_cli_defaults, load_settings
```
