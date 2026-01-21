from typing import List, Dict, Optional, Any
import time
import structlog
from googleapiclient.errors import HttpError
from .client import build_gkebackup, build_container, list_gke_clusters

log = structlog.get_logger()

class GKEBackupManager:
    def __init__(self, credentials, project_id: str):
        self.creds = credentials
        self.project_id = project_id
        self.backup_client = build_gkebackup(credentials)
        self.container_client = build_container(credentials)

    def list_clusters(self) -> List[Dict]:
        """List all GKE clusters in the project."""
        return list_gke_clusters(self.container_client, self.project_id)

    def list_backup_plans(self, location: str = "-") -> List[Dict]:
        """List all GKE Backup Plans in the project/location."""
        # Try specific location first
        locations_to_try = [location]
        if location != "-" and location != "europe-west1":
             locations_to_try.append("europe-west1")
        
        all_items = []
        for loc in locations_to_try:
            parent = f"projects/{self.project_id}/locations/{loc}"
            try:
                req = self.backup_client.projects().locations().backupPlans().list(parent=parent)
                while req:
                    resp = req.execute()
                    plans = resp.get("backupPlans", [])
                    # Enrich plans with actual location found
                    for p in plans:
                        p['_actual_location'] = loc
                    all_items.extend(plans)
                    req = self.backup_client.projects().locations().backupPlans().list_next(previous_request=req, previous_response=resp)
                # If we found items in the specific location, we might not need to look further, 
                # but plans could be split. For safety, we can look at both.
            except HttpError as e:
                # If permission denied or not found, try next location or just log debug
                log.debug("failed_to_list_backup_plans", project=self.project_id, location=loc, error=str(e))
        
        return all_items

    def list_backups(self, plan_full_name: str) -> List[Dict]:
        """List all backups for a given plan."""
        try:
            req = self.backup_client.projects().locations().backupPlans().backups().list(parent=plan_full_name)
            items = []
            while req:
                resp = req.execute()
                items.extend(resp.get("backups", []))
                req = self.backup_client.projects().locations().backupPlans().backups().list_next(previous_request=req, previous_response=resp)
            return items
        except HttpError as e:
            log.warning("failed_to_list_backups", plan=plan_full_name, error=str(e))
            return []

    def get_backup_plan(self, plan_name: str) -> Optional[Dict]:
        """Get a specific backup plan."""
        try:
            return self.backup_client.projects().locations().backupPlans().get(name=plan_name).execute()
        except HttpError:
            return None

    def create_backup_plan(self, cluster_id: str, location: str, plan_id: str, retention_days: int = 7) -> Dict:
        """Create a default backup plan for a cluster."""
        parent = f"projects/{self.project_id}/locations/{location}"
        cluster_full_name = f"projects/{self.project_id}/locations/{location}/clusters/{cluster_id}"
        
        body = {
            "cluster": cluster_full_name,
            "backupConfig": {
                "allNamespaces": True,
                "includeVolumeData": True,
                "includeSecrets": True,
            },
            "retentionPolicy": {
                "backupRetainDays": retention_days,
            },
            # "cronSchedule": ... # Optional: we can add schedule later or rely on manual
        }
        
        try:
            req = self.backup_client.projects().locations().backupPlans().create(
                parent=parent,
                backupPlanId=plan_id,
                body=body
            )
            op = req.execute()
            log.info("backup_plan_creation_initiated", plan=plan_id, operation=op.get("name"))
            return op
        except HttpError as e:
            log.error("failed_to_create_backup_plan", plan=plan_id, error=str(e))
            raise

    def create_backup(self, plan_full_name: str) -> Dict:
        """Trigger a backup for a given plan."""
        # plan_full_name format: projects/*/locations/*/backupPlans/*
        backup_id = f"manual-{int(time.time())}"
        body = {
            "description": "Triggered via Fulcrum CLI",
            "deleteLockDays": 0
        }
        try:
            req = self.backup_client.projects().locations().backupPlans().backups().create(
                parent=plan_full_name,
                backupId=backup_id,
                body=body
            )
            op = req.execute()
            log.info("backup_initiated", backup=backup_id, plan=plan_full_name)
            return op
        except HttpError as e:
            log.error("failed_to_trigger_backup", plan=plan_full_name, error=str(e))
            raise

    def check_backup_status(self, backup_full_name: str) -> Dict:
        """Check status of a backup."""
        try:
            return self.backup_client.projects().locations().backupPlans().backups().get(name=backup_full_name).execute()
        except HttpError:
            return {}
