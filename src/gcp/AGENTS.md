# GCP Integration Module

13 modules for GCP asset discovery, API clients, and remediation.

## Overview

GCP API client wrappers, asset discovery functions, and remediation logic for Cloud SQL, GKE, IAP, and logging quotas.

## Structure

```
src/gcp/
├── client.py               # API client builders & list_* functions
├── native_client.py        # Native API wrappers (278 lines - KEY)
├── auth.py                 # Authentication utilities
├── runner.py               # Discovery runner orchestration
├── remediation.py          # Generic remediation
├── iap_remediation.py      # IAP-specific fixes (152 lines)
├── logging_quota.py        # Logging quota fixes (72 lines)
├── audit_functions.py      # Audit-related functions
├── discover_iap.py         # IAP discovery
├── backup.py               # Backup utilities
├── decommission.py         # Decommission utilities
├── artifact_registry.py    # Artifact Registry discovery
└── __init__.py
```

## Where to Look

| Task | File | Notes |
|------|------|-------|
| GCP API clients | `client.py` | `build_compute()`, `list_instances()`, `list_firewalls()` |
| Complex discovery | `native_client.py` | 278 lines - comprehensive native wrappers |
| IAP remediation | `iap_remediation.py` | 152 lines - IAP-specific fixes |
| Orchestration | `runner.py` | Runs discovery across projects |

## Key Functions

| Function | Purpose |
|----------|---------|
| `build_compute(creds)` | Build Compute Engine API client |
| `build_crm(creds)` | Build Cloud Resource Manager client |
| `build_storage_client(creds)` | Build GCS client |
| `list_instances(compute, project)` | Aggregate instances across zones |
| `list_firewalls(compute, project)` | List firewall rules |
| `list_subnetworks(compute, project)` | List subnetworks |
| `list_clusters(container, project)` | List GKE clusters |

## Conventions

- **API Caching**: `cache_discovery=False` in `build()` calls
- **Pagination**: Use `*_next()` pattern for aggregated lists
- **Retries**: `num_retries=2` on API calls
- **Credentials**: Always pass `creds` parameter, never store globally

## Anti-Patterns

- **NO** hardcoded project IDs—pass as parameters
- **NO** blocking calls in async context
- **NO** raw credential handling—use `google-auth` patterns

## Dependencies

- `google-api-python-client`
- `google-auth`
- `google-cloud-storage`
- `google-cloud-compute`
- `google-cloud-resource-manager`
- `google-cloud-container`
