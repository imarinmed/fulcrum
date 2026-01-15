# Security Dashboard

The Fulcrum Security Dashboard provides a comprehensive, interactive interface for viewing and analyzing security findings from Prowler scans, local security audits, and port exposure checks.

## Overview

The Security Dashboard transforms raw security data into an engaging, easy-to-understand visual experience with:

- **Security Score Gauge** - Animated radial gauge showing overall security posture (0-100)
- **Severity Distribution** - Visual breakdown of findings by severity level
- **Compliance Dashboard** - Framework compliance status for CIS, HIPAA, GDPR, SOC2, PCI, NIST, ISO27001
- **Findings Explorer** - Filterable, sortable table with detailed finding information
- **Remediation Actions** - Auto-fixable and manual remediation guidance
- **Trend Analysis** - Historical security posture tracking
- **Export Capabilities** - Export findings to JSON, CSV, or Markdown reports

## Launching the Security Dashboard

```bash
# From report output directory
uv run python -m fulcrum dashboard --out-dir master-report

# Or with explicit project
uv run python -m fulcrum dashboard --out-dir ./security-report
```

## Navigation

### Main View Navigation

| Key | View |
|-----|------|
| `c` | Compute resources |
| `s` | Storage resources |
| `n` | Networking resources |
| `k` | Kubernetes resources |
| `y` | **Security Dashboard** |
| `e` | Executive report |
| `?` | Show help |

### Security Dashboard Sub-Views

| Key | View | Description |
|-----|------|-------------|
| `o` | Overview | Security score, metrics, critical findings |
| `f` | Findings | Filterable findings table |
| `m` | Compliance | Framework compliance status |
| `r` | Remediation | Fix recommendations and actions |
| `t` | Trends | Historical security trends |

## Views Details

### Overview (`o`)

The Overview panel provides a quick snapshot of your security posture:

- **Security Score** (0-100) - Color-coded: Green (80+), Yellow (60-79), Red (<60)
- **Risk Level** - CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
- **Metrics Panel** - Critical issues, high priority, total failing
- **Severity Distribution** - Horizontal bar chart showing finding counts
- **Service Distribution** - Findings breakdown by GCP service
- **Critical Findings** - Quick access to top critical issues

### Findings (`f`)

The Findings panel provides detailed security findings with powerful filtering:

#### Filter Bar

- **Search** - Full-text search across check ID, description, service, resource
- **Severity Filters** - 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low
- **Clear Filters** - Reset all filters

#### Table Columns

| Column | Description |
|--------|-------------|
| Severity | Finding severity level |
| Status | PASS/FAIL/WARNING status |
| Check ID | Prowler check identifier |
| Service | GCP service (compute, iam, storage, etc.) |
| Framework | Compliance framework |
| Description | Finding description |

#### Sorting

Findings are automatically sorted by:
1. Severity (Critical → Low)
2. Status (Fail → Pass)
3. Check ID

### Compliance (`m`)

The Compliance panel shows security framework compliance status:

#### Supported Frameworks

| Framework | Icon | Description |
|-----------|------|-------------|
| CIS | 🏛️ | CIS Benchmarks |
| HIPAA | 🏥 | Healthcare compliance |
| GDPR | 🇪🇺 | EU data protection |
| SOC2 | 📋 | Service organization control |
| PCI | 💳 | Payment card industry |
| NIST | 🔒 | NIST security controls |
| ISO27001 | 📜 | Information security |

#### Compliance Score

Each framework shows:
- Compliance percentage (0-100%)
- Pass/Fail check counts
- Status indicator (✅ Compliant, ⚠️ Needs Improvement)

### Remediation (`r`)

The Remediation panel provides actionable guidance:

#### Auto-Fixable Issues

Issues that can be fixed automatically:
- GKE insecure kubelet port
- IAP configuration issues
- Logging quota problems

Click to execute remediation.

#### Manual Remediation

Step-by-step guidance for manual fixes:
- Detailed remediation steps
- gcloud command examples
- Links to GCP documentation
- Estimated time to fix

### Trends (`t`)

The Trends panel shows security posture over time:

- **Current Score** - Your security score
- **Trend Direction** - 📈 Improving, 📉 Declining, ➡️ Stable
- **Finding Volume** - Total findings, failing, passing
- **Severity Breakdown** - Critical, High, Medium, Low counts

## Export Functionality

### Export Formats

```python
from src.ui.security.store import SecurityStore

store = SecurityStore("./master-report")

# Export all findings to JSON
store.export_findings_json("findings.json")

# Export filtered findings to CSV
filters = FindingFilters(severities={Severity.CRITICAL})
store.export_findings_csv("critical_findings.csv", filters)

# Export compliance report
store.export_compliance_report("compliance_report.md")

# Export specific framework
store.export_compliance_report("cis_compliance.md", Framework.CIS)
```

### Export Formats Comparison

| Format | Use Case | Contents |
|--------|----------|----------|
| JSON | programmatic analysis | Full finding data with metadata |
| CSV | Spreadsheet analysis | Tabular data for Excel/Sheets |
| Markdown | Documentation | Human-readable report with tables |
| Compliance Report | Audit preparation | Framework-specific detailed report |

### Filtered Exports

Apply filters before exporting:

```python
from src.ui.security.store import SecurityStore, FindingFilters, Severity

store = SecurityStore("./report")

# Export only critical and high severity findings
filters = FindingFilters(
    severities={Severity.CRITICAL, Severity.HIGH},
    show_only_failures=True
)

store.export_findings_markdown("critical_issues.md", filters)
```

## Data Sources

The Security Dashboard aggregates findings from:

1. **Prowler Scans** - OCSF JSON format from `prowler_output/*.ocsf.json`
2. **Local Security Audit** - JSON format from `security_audit.json`
3. **Port Check Results** - JSON format from `port_*.json`

### Expected File Structure

```
master-report/
├── prowler_output/
│   ├── project-1.ocsf.json
│   └── project-2.ocsf.json
├── security_audit.json
└── port_22_report.json
```

## Security Score Calculation

The security score (0-100) is calculated based on failing findings:

| Severity | Deduction |
|----------|-----------|
| Critical | -15 points |
| High | -10 points |
| Medium | -5 points |
| Low | -1 point |
| Informational | 0 points |

**Formula**: `Score = 100 - Σ(severity deductions)`

### Risk Level Thresholds

| Score Range | Risk Level | Critical Issues |
|-------------|------------|-----------------|
| 86-100 | MINIMAL | None |
| 71-85 | LOW | None |
| 51-70 | MEDIUM | None |
| 31-50 | HIGH | None |
| 0-30 | CRITICAL | 1+ |

## Architecture

### Component Structure

```
src/ui/security/
├── store.py           # SecurityStore, SecurityData, findings models
├── components.py      # Gauge, Distribution, Cards, Badges
├── findings.py        # FindingsTable, FindingFilterBar
├── panels.py          # Overview, Compliance, Remediation, Trends panels
└── __init__.py        # Public API exports
```

### Key Classes

| Class | Purpose |
|-------|---------|
| `SecurityStore` | Centralized data management with caching |
| `SecurityData` | Aggregated security findings and statistics |
| `SecurityFinding` | Normalized finding model |
| `FindingFilters` | Filter criteria for findings |
| `SecurityScoreGauge` | Animated radial score display |
| `FindingsTable` | Filterable findings data table |
| `CompliancePanel` | Framework compliance visualization |

### Extensibility

The Security Dashboard is designed for extensibility:

```python
from src.ui.security.store import SecurityStore, SecurityFinding

# Custom finding source
class CustomSecurityStore(SecurityStore):
    def _load_custom_findings(self) -> List[SecurityFinding]:
        # Load from your custom source
        pass

# Plugin architecture for new panels
class CustomPanel(Container):
    def compose(self) -> ComposeResult:
        # Your custom panel
        pass
```

## Keyboard Shortcuts Reference

### Global

| Key | Action |
|-----|--------|
| `?` | Show help |
| `Esc` | Clear filters / Close drawer |

### Navigation

| Key | Action |
|-----|--------|
| `c` | Compute view |
| `s` | Storage view |
| `n` | Networking view |
| `k` | Kubernetes view |
| `y` | Security Dashboard |
| `e` | Executive report |

### Security Dashboard

| Key | Action |
|-----|--------|
| `o` | Overview panel |
| `f` | Findings panel |
| `m` | Compliance panel |
| `r` | Remediation panel |
| `t` | Trends panel |

## Troubleshooting

### No Findings Displayed

1. Check that Prowler output exists: `ls prowler_output/*.ocsf.json`
2. Verify report directory structure
3. Check file permissions

### Security Score Not Calculated

1. Ensure findings have valid severity levels
2. Check that findings are loaded correctly
3. Verify no parsing errors in logs

### Export Fails

1. Check write permissions in output directory
2. Verify file is not open in another program
3. Ensure sufficient disk space

## Performance

- **Data Loading**: Findings are cached for 5 minutes (configurable)
- **Table Rendering**: Limited to 100 rows for performance
- **Large Datasets**: Use filters to reduce displayed findings

### Cache Management

```python
# Force refresh data
store.invalidate_cache()
store.load_security_data(force_refresh=True)

# Clear all cache
store.clear_cache()
```

## Integration with CI/CD

```bash
# Generate security report and export findings
uv run python -c "
from src.ui.security.store import SecurityStore
store = SecurityStore('./report')
store.export_findings_json('findings.json')
store.export_compliance_report('compliance.md')
"
```

## Best Practices

1. **Regular Scans**: Run Prowler scans regularly (weekly/daily)
2. **Review Critical Findings**: Address critical issues immediately
3. **Track Trends**: Monitor security score trends over time
4. **Export Reports**: Maintain audit trail with exported reports
5. **Automate Remediation**: Use auto-fixable remediation where possible
