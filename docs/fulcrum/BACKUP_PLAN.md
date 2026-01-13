# Comprehensive Kubernetes Backup Plan for Fulcrum Projects

**Date:** 2025-12-15  
**Priority:** Immediate (Implementation before Dec 16)  
**Status:** Draft / In Implementation

## 1. Detailed Inventory

To ensure complete coverage, we must first catalog all existing Kubernetes assets within the Fulcrum-managed GCP scope.

### 1.1 Cluster Identification
**Action:** Automatically discover all GKE clusters across managed projects.
- **Source:** GCP Cloud Asset Inventory & GKE API.
- **Attributes to Catalog:**
  - Project ID
  - Cluster Name
  - Location (Region/Zone)
  - GKE Version
  - Node Pools (Size, Machine Type)

### 1.2 Critical Workloads & Namespaces
**Action:** Classify namespaces and applications based on criticality.
- **Critical Namespaces:** `default`, `kube-system` (config only), and custom application namespaces (e.g., `app-*`, `data-*`).
- **Excluded Namespaces:** `kube-node-lease`, `kube-public`.
- **Priority Applications:** StatefulSets and Deployments with PersistentVolumeClaims (PVCs).

### 1.3 Recovery Objectives (RPO/RTO)
| Workload Type | RPO (Data Loss Tolerance) | RTO (Downtime Tolerance) | Backup Frequency |
|---------------|---------------------------|--------------------------|------------------|
| **Stateless** | 24 Hours (Config)         | 1 Hour                   | Daily            |
| **Stateful DB**| 1 Hour                   | 4 Hours                  | Hourly/Daily     |
| **Config/Secrets**| 24 Hours              | 1 Hour                   | Daily            |

## 2. Backup Strategy

We will leverage **GCP Native Backup for GKE** (Backup for GKE) where available, supplemented by custom snapshot logic for granular control via Fulcrum.

### 2.1 Technology Stack
- **Primary:** [Backup for GKE](https://cloud.google.com/kubernetes-engine/docs/add-on/backup-for-gke/concepts/backup-for-gke) (GCP Native).
- **Orchestrator:** Fulcrum CLI (`fulcrum backup`).
- **Storage:** GCP Cloud Storage (Multi-region buckets for DR).

### 2.2 Retention Policies
- **Daily Backups:** Retained for 7 days.
- **Weekly Backups:** Retained for 4 weeks.
- **Monthly Backups:** Retained for 12 months.

### 2.3 Scope of Backup
1.  **Persistent Volumes:** Volume snapshots via CSI drivers (PD-CS).
2.  **Kubernetes Objects:**
    - Manifests (Deployments, Services, StatefulSets).
    - Configuration (ConfigMaps, Secrets - encrypted).
    - Custom Resource Definitions (CRDs).

## 3. Automation in Fulcrum

Integration of backup workflows into the `fulcrum` CLI tool.

### 3.1 New CLI Commands
The following commands will be implemented:
- `fulcrum backup inventory --project <ID>`: List clusters and their backup eligibility.
- `fulcrum backup protect --project <ID>`: Automatically apply backup policies (Backup Plans) to unprotected clusters.
- `fulcrum backup run --project <ID>`: Trigger an immediate backup for all clusters in the project.
- `fulcrum backup list --project <ID>`: List the actual backups (snapshots) that have been created, showing their status and creation time.
- `fulcrum backup plan --project <ID>`: View the retention policy and schedule configuration.

### 3.2 Protection Workflow
The recommended workflow for managing backups is:
1.  **Inventory**: Run `fulcrum backup inventory` to identify unprotected clusters.
2.  **Protect**: Run `fulcrum backup protect` to auto-configure Backup Plans (7-day retention by default).
3.  **Run**: Run `fulcrum backup run` to execute backups (or schedule this via cron).
4.  **Verify**: Run `fulcrum backup list` to confirm backups are successfully created (`SUCCEEDED` state).

### 3.3 Validations (Pre/Post)
- **Pre-Backup Checks:**
  - Verify `Backup for GKE` API is enabled.
  - Check permissions (`backup-admin` role).
  - Validate PVC health (Bound state).
- **Post-Backup Checks:**
  - Verify Backup Job Status = `SUCCEEDED`.
  - Validate Snapshot existence in GCS.

### 3.3 Alerting
- **Failure Notification:** Log errors to `structlog` (which can be piped to Cloud Logging/Monitoring).
- **Dashboard:** Update Fulcrum Dashboard to show Backup Status (Last Backup Time, Status).

## 4. Verification and Tests

### 4.1 Restoration Testing
- **Scenario A:** Namespace deletion (Accidental). Restore single namespace.
- **Scenario B:** Cluster Corruption. Restore to new cluster.
- **Scenario C:** Region Failure. Restore to alternate region (DR).

### 4.2 Disaster Recovery (DR) Documentation
- Step-by-step guide to restore a cluster using `fulcrum backup restore` (future implementation) or GCP Console.

### 4.3 Success Metrics
- **Backup Success Rate:** > 99%.
- **Restore Success Rate:** 100% in quarterly drills.

## 5. Delivery and Training

### 5.1 Documentation
- This plan resides in `docs/fulcrum/BACKUP_PLAN.md`.
- Architecture diagrams to be added to `docs/ARCHITECTURE.md`.

### 5.2 Implementation Checklist for New Clusters
- [ ] Enable `Backup for GKE` feature on cluster.
- [ ] Grant Fulcrum Service Account permissions.
- [ ] Verify inclusion in `fulcrum backup inventory`.

### 5.3 Training
- Team workshop on executing backups and restores using Fulcrum CLI.
