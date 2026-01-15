# Prowler Integration Module

9 modules for security scan ingestion, parsing, and normalization.

## Overview

Integrates Prowler security scanner results. Parses JSON/CSV, normalizes findings to canonical form, and aggregates for reporting.

## Structure

```
src/prowler/
├── models.py              # Pydantic models (247 lines - KEY)
├── runner.py              # Scan runner & check listing
├── scanner.py             # Async scanner wrapper
├── parser.py              # Raw finding parsers
├── normalize.py           # Normalization logic (93 lines)
├── aggregator.py          # Report aggregation (136 lines)
├── api.py                 # Prowler API wrappers
├── mapping.py             # Check ID to framework mapping
└── __init__.py
```

## Where to Look

| Task | File | Notes |
|------|------|-------|
| Data models | `models.py` | **Start here** - defines `CanonicalFinding`, `Severity`, `Framework` |
| Normalization | `normalize.py` | Convert raw Prowler output → canonical form |
| Aggregation | `aggregator.py` | Aggregate findings across projects |
| Running scans | `runner.py` | `run_scan()`, `list_checks()` |

## Key Classes (from `models.py`)

| Class | Purpose |
|-------|---------|
| `CanonicalFinding` | Normalized security finding (project_id, check_id, severity, framework, etc.) |
| `Severity` | Enum: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL |
| `Status` | Enum: PASS, FAIL, WARNING, UNKNOWN |
| `Framework` | Enum: CIS, HIPAA, GDPR, SOC2, PCI, NIST, ISO27001 |
| `RawProwlerFinding` | Raw input model for parsing |

## Key Classes (from `aggregator.py`)

| Class | Purpose |
|-------|---------|
| `ReportAggregator` | Aggregates findings into report-ready structure |
| `FindingSummary` | Summary statistics by severity/framework |

## Conventions

- **Pydantic v2**: Use `model_config = ConfigDict(use_enum_values=True)`
- **Validation**: All validation in Pydantic models, not in business logic
- **Enums**: String enums with `use_enum_values=True` for serialization

## Anti-Patterns

- **NO** raw dict access—use Pydantic field access
- **NO** string literals for severity/framework—use enums
- **NO** direct JSON parsing—use Pydantic models

## Command Integration

```python
from .runner import list_checks, run_scan
from .aggregator import ReportAggregator
from .models import CanonicalFinding
```

## Output Formats

- **JSON**: Raw Prowler output
- **CSV**: Tabular findings
- **Normalized**: `CanonicalFinding` objects for internal use
