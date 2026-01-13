# Fulcrum CLI User Guide

Fulcrum CLI provides tools for reporting, security scanning, and remediation.

## Core Commands

### Reporting
Generate standard reports:
```bash
fulcrum reports standard --out-base reports
```

### Security
Run Prowler scans:
```bash
fulcrum reports security run --projects my-project
```

### Remediation (New)
Apply automated fixes for identified issues.

**Fix an issue:**
```bash
fulcrum fix [ISSUE_ID] [TARGET_JSON]
```
Example:
```bash
fulcrum fix cis_gke_v1_6_0_4_2_4 '{"project_id": "marcablanca", "cluster_name": "gke-cluster-1", "location": "europe-west1"}'
```

**Diagnose system health:**
```bash
fulcrum diagnose
```

**View History:**
```bash
fulcrum history
```

## Configuration
Manage settings via `fulcrum config`.
```bash
fulcrum config show
```
