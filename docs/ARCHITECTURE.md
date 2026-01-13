# Fulcrum Architecture

## Overview
Fulcrum is a reporting and remediation engine for Google Cloud Platform (GCP). It provides:
- **Reporting**: Standardized Markdown reports for GCP resources (Compute, Networking, GKE, etc.).
- **Security**: Integration with Prowler for security scanning.
- **Diagnostics**: Health checks for the reporting engine and target environment.
- **Remediation**: Automated fixes for identified security issues (Self-healing).

## Core Components

### Reporting Subsystem (`src/core/reporting.py`)
Responsible for generating reports. Key features:
- **System Snapshot**: Captures system state (timestamp, versions, settings) at report time.
- **History Manager**: Tracks historical reports for trend analysis.

### Diagnostics (`src/core/diagnostics.py`)
Runs checks to ensure the system is healthy.
- `DiagnosticsManager`: Orchestrates checks.
- `DiagnosticCheck`: Abstract base class for individual checks.

### Remediation (`src/core/remediation.py`)
Handles automated fixes.
- `RemediationManager`: Registry and executor for remediation actions.
- `RemediationAction`: Abstract base class for a fix (e.g., "Disable Insecure Port").
- **GCP Remediation** (`src/gcp/remediation.py`): Implementations specific to GCP (e.g., `GKEReadOnlyPortRemediation`).

### Backup & DR (`src/core/backup.py`)
Manages Kubernetes backup lifecycle.
- `BackupOrchestrator`: Coordinates discovery and backup execution.
- `GKEBackupManager`: Wraps the `gkebackup` GCP API for plan/backup management.

## Data Flow
1.  **Collect**: `src/core/collect.py` gathers data from GCP APIs.
2.  **Scan**: `src/prowler/runner.py` runs Prowler scans.
3.  **Report**: `src/core/reporting.py` combines data into Markdown/JSON.
4.  **Remediate**: `src/cli.py` triggers `RemediationManager` based on finding IDs.
5.  **Backup**: `src/cli.py` invokes `BackupOrchestrator` to protect critical assets.
