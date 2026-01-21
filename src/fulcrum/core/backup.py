from typing import List, Dict, Any
from ..gcp.backup import GKEBackupManager
from ..gcp.auth import load_credentials
from ..core.settings import load_settings
import structlog

log = structlog.get_logger()

class BackupOrchestrator:
    def __init__(self, project_id: str, sa_key_path: str = None):
        self.project_id = project_id
        # Load settings to check for SA key if not provided
        if not sa_key_path:
            s = load_settings(None)
            sa_key_path = s.credentials.sa_key_path
        
        creds, _ = load_credentials(sa_key_path)
        self.mgr = GKEBackupManager(creds, project_id)

    def inventory(self) -> List[Dict[str, Any]]:
        """
        Generate an inventory of clusters and their backup status.
        """
        try:
            clusters = self.mgr.list_clusters()
        except Exception as e:
            log.error("failed_to_list_clusters", project=self.project_id, error=str(e))
            return []

        # We need to query plans per location, but list_backup_plans takes location.
        # Clusters can be in different locations.
        # Optimization: Collect unique locations from clusters.
        locations = set(c['location'] for c in clusters)
        all_plans = []
        for loc in locations:
            all_plans.extend(self.mgr.list_backup_plans(loc))

        inventory = []
        for c in clusters:
            c_name = c['name']
            c_loc = c['location']
            # Full cluster name format in Backup Plan: projects/{project}/locations/{location}/clusters/{cluster}
            c_full = f"projects/{self.project_id}/locations/{c_loc}/clusters/{c_name}"
            
            matched_plans = [p for p in all_plans if p.get('cluster') == c_full]
            
            # Detect location mismatch
            location_mismatch = None
            if matched_plans:
                actual_loc = matched_plans[0].get('_actual_location')
                if actual_loc and actual_loc != c_loc:
                    location_mismatch = f"{c_loc} -> {actual_loc}"

            inventory.append({
                "project": self.project_id,
                "cluster": c_name,
                "location": c_loc,
                "status": c.get('status'),
                "backup_plans": [p['name'].split('/')[-1] for p in matched_plans],
                "backup_plan_full_names": [p['name'] for p in matched_plans],
                "protected": len(matched_plans) > 0,
                "location_mismatch": location_mismatch,
                "version": c.get('currentMasterVersion')
            })
        return inventory

    def get_backup_plans_details(self) -> List[Dict[str, Any]]:
        """
        Get full details of all backup plans for the project.
        """
        inv = self.inventory()
        plans_details = []
        
        # We need to list plans again or extract from inventory if we had full details.
        # But inventory only has names. Let's list all plans properly using manager.
        # We can reuse the location logic from inventory.
        
        clusters = self.mgr.list_clusters()
        locations = set(c['location'] for c in clusters)
        all_plans = []
        for loc in locations:
            all_plans.extend(self.mgr.list_backup_plans(loc))
            
        for p in all_plans:
            # Add cluster mapping for convenience
            cluster_full = p.get('cluster', '')
            cluster_short = cluster_full.split('/')[-1] if cluster_full else "Unknown"
            
            plans_details.append({
                "name": p.get('name', '').split('/')[-1],
                "full_name": p.get('name'),
                "cluster": cluster_short,
                "location": p.get('name', '').split('/')[3], # Extract location from full name
                "retention_days": p.get('retentionPolicy', {}).get('backupRetainDays'),
                "backup_config": p.get('backupConfig', {}),
                "cron_schedule": p.get('cronSchedule', {}).get('cronSchedule'),
                "raw": p
            })
            
        return plans_details

    def list_cluster_backups(self) -> List[Dict[str, Any]]:
        """
        List all backups across all protected clusters.
        """
        inv = self.inventory()
        results = []
        for item in inv:
            if item['protected'] and item.get('backup_plan_full_names'):
                # Check backups for each plan (usually one)
                for plan_full in item['backup_plan_full_names']:
                    plan_short = plan_full.split('/')[-1]
                    backups = self.mgr.list_backups(plan_full)
                    if not backups:
                        results.append({
                            "project": self.project_id,
                            "cluster": item['cluster'],
                            "plan": plan_short,
                            "backup_name": "-",
                            "state": "NO_BACKUPS",
                            "create_time": "-"
                        })
                    for b in backups:
                        results.append({
                            "project": self.project_id,
                            "cluster": item['cluster'],
                            "plan": plan_short,
                            "backup_name": b['name'].split('/')[-1],
                            "state": b.get('state'),
                            "create_time": b.get('createTime')
                        })
            else:
                results.append({
                    "project": self.project_id,
                    "cluster": item['cluster'],
                    "plan": "-",
                    "backup_name": "-",
                    "state": "UNPROTECTED",
                    "create_time": "-"
                })
        return results

    def protect_unprotected_clusters(self, retention_days: int = 7) -> List[Dict[str, Any]]:
        """
        Create backup plans for all unprotected clusters.
        """
        inv = self.inventory()
        results = []
        for item in inv:
            if not item['protected']:
                cluster_name = item['cluster']
                location = item['location']
                plan_id = f"fulcrum-protection-{cluster_name}"
                
                try:
                    op = self.mgr.create_backup_plan(
                        cluster_id=cluster_name,
                        location=location,
                        plan_id=plan_id,
                        retention_days=retention_days
                    )
                    results.append({
                        "cluster": cluster_name,
                        "plan": plan_id,
                        "status": "Created",
                        "operation": op.get("name")
                    })
                except Exception as e:
                    results.append({
                        "cluster": cluster_name,
                        "plan": plan_id,
                        "status": "Failed",
                        "error": str(e)
                    })
            else:
                results.append({
                    "cluster": item['cluster'],
                    "plan": "-",
                    "status": "Skipped",
                    "reason": "Already protected"
                })
        return results

    def run_backup(self) -> List[Dict[str, Any]]:
        """
        Trigger backups for all protected clusters.
        """
        inv = self.inventory()
        results = []
        for item in inv:
            if item['backup_plans']:
                # Use the first plan found
                plan_id = item['backup_plans'][0]
                plan_full = f"projects/{self.project_id}/locations/{item['location']}/backupPlans/{plan_id}"
                try:
                    op = self.mgr.create_backup(plan_full)
                    results.append({
                        "cluster": item['cluster'],
                        "plan": plan_id,
                        "status": "Initiated",
                        "operation": op.get("name")
                    })
                except Exception as e:
                    results.append({
                        "cluster": item['cluster'],
                        "plan": plan_id,
                        "status": "Failed",
                        "error": str(e)
                    })
            else:
                results.append({
                    "cluster": item['cluster'],
                    "plan": "-",
                    "status": "Skipped",
                    "reason": "No Backup Plan configured"
                })
        return results
