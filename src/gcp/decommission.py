import json
import time
import structlog
from typing import List, Dict, Any, Optional
from .runner import run_gcloud_json, GCloudError
import subprocess

log = structlog.get_logger()

class Decommissioner:
    def __init__(self, project_id: str):
        self.project_id = project_id
        # Whitelist of buckets to preserve
        self.bucket_whitelist = ["breogan-shared-bucket"]

    def audit_resources(self) -> Dict[str, Any]:
        """List all resources to be decommissioned."""
        report = {
            "project_id": self.project_id,
            "gke_clusters": [],
            "sql_instances": [],
            "buckets": [],
            "forwarding_rules": []
        }
        
        log.info("decom.audit_start", project=self.project_id)
        
        # GKE
        try:
            log.info("decom.audit_gke", project=self.project_id)
            clusters = run_gcloud_json(["container", "clusters", "list", "--project", self.project_id])
            for c in clusters:
                report["gke_clusters"].append({"name": c.get("name"), "location": c.get("location")})
        except GCloudError as e:
            log.warning("decom.audit_gke_error", error=str(e))

        # SQL
        try:
            log.info("decom.audit_sql", project=self.project_id)
            sqls = run_gcloud_json(["sql", "instances", "list", "--project", self.project_id])
            for s in sqls:
                report["sql_instances"].append({"name": s.get("name"), "region": s.get("region")})
        except GCloudError as e:
            log.warning("decom.audit_sql_error", error=str(e))

        # Buckets
        try:
            log.info("decom.audit_buckets", project=self.project_id)
            buckets = run_gcloud_json(["storage", "buckets", "list", "--project", self.project_id])
            for b in buckets:
                # simple name extraction from gs://name/
                # list returns dict with 'id' usually being the name
                name = b.get("id", "").replace("gs://", "").rstrip("/") # id usually matches name
                if not name: name = b.get("name") # fallback
                
                action = "DELETE"
                if any(w in name for w in self.bucket_whitelist):
                    action = "PRESERVE"
                
                report["buckets"].append({"name": name, "action": action})
        except GCloudError as e:
            log.warning("decom.audit_buckets_error", error=str(e))
        
        # Networking (LBs/Forwarding Rules)
        try:
            log.info("decom.audit_network", project=self.project_id)
            fwds = run_gcloud_json(["compute", "forwarding-rules", "list", "--project", self.project_id])
            for f in fwds:
                report["forwarding_rules"].append({"name": f.get("name"), "region": f.get("region")})
        except GCloudError as e:
            log.warning("decom.audit_network_error", error=str(e))

        return report

    def backup_sql(self) -> List[str]:
        """Trigger on-demand backups for all SQL instances."""
        snapshots = []
        try:
            sqls = run_gcloud_json(["sql", "instances", "list", "--project", self.project_id])
            for s in sqls:
                name = s.get("name")
                desc = f"final-backup-{int(time.time())}"
                log.info("decom.backup_sql_start", instance=name)
                # gcloud sql backups create --instance=NAME --description=DESC --async
                # We do sync here to ensure it finishes? No, sync takes too long. Async + verify later?
                # For this tool, let's trigger async and report.
                cmd = ["sql", "backups", "create", "--instance", name, "--description", desc, "--project", self.project_id, "--quiet"]
                try:
                    subprocess.run(["gcloud"] + cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    snapshots.append(f"{name}:{desc}")
                    log.info("decom.backup_sql_triggered", instance=name)
                except subprocess.CalledProcessError as e:
                    log.error("decom.backup_sql_failed", instance=name, error=str(e))
        except GCloudError: pass
        return snapshots

    def cordon_clusters(self):
        """Cordon all nodes in all clusters."""
        # 1. List clusters
        # 2. Get credentials
        # 3. kubectl cordon nodes --all
        # Requires kubectl context switching which is tricky in CLI.
        # Alternatively, resize node pools to 0? That's effectively destroying.
        # Cordon is safer.
        # Given env limitations, maybe we skip kubectl and just document?
        # Or we can try to get credentials and run kubectl.
        try:
            clusters = run_gcloud_json(["container", "clusters", "list", "--project", self.project_id])
            for c in clusters:
                name = c.get("name")
                loc = c.get("location")
                log.info("decom.cordon_start", cluster=name)
                
                # Get creds
                get_cred = ["container", "clusters", "get-credentials", name, "--project", self.project_id]
                if loc:
                    # check if region or zone
                    # usually location field covers it (e.g. europe-west1 or europe-west1-b)
                    # --region or --zone flag
                    # simplistic heuristic: count dashes? no.
                    # gcloud accepts --region or --zone. list output has 'location'.
                    # We can use --location (newer gcloud) or try to parse.
                    get_cred.extend(["--location", loc])
                
                try:
                    subprocess.run(["gcloud"] + get_cred, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    # Cordon
                    # kubectl get nodes -o name | xargs kubectl cordon
                    subprocess.run("kubectl get nodes -o name | xargs kubectl cordon", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    log.info("decom.cordon_success", cluster=name)
                except subprocess.CalledProcessError as e:
                    log.error("decom.cordon_failed", cluster=name, error=str(e))
                    
        except GCloudError: pass

    def destroy_resources(self, dry_run: bool = True):
        """Destroy resources based on audit."""
        report = self.audit_resources()
        
        # GKE
        for c in report["gke_clusters"]:
            name = c["name"]
            loc = c["location"]
            if dry_run:
                log.info("decom.destroy_dry_run", type="GKE", name=name)
            else:
                log.info("decom.destroying", type="GKE", name=name)
                # gcloud container clusters delete NAME --location LOC --quiet
                cmd = ["container", "clusters", "delete", name, "--project", self.project_id, "--quiet"]
                if loc: cmd.extend(["--location", loc])
                try:
                    subprocess.run(["gcloud"] + cmd, check=True, stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError as e:
                    log.error("decom.destroy_failed", name=name, error=str(e))

        # SQL
        for s in report["sql_instances"]:
            name = s["name"]
            if dry_run:
                log.info("decom.destroy_dry_run", type="SQL", name=name)
            else:
                log.info("decom.destroying", type="SQL", name=name)
                cmd = ["sql", "instances", "delete", name, "--project", self.project_id, "--quiet"]
                try:
                    subprocess.run(["gcloud"] + cmd, check=True, stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError as e:
                    log.error("decom.destroy_failed", name=name, error=str(e))

        # Buckets
        for b in report["buckets"]:
            name = b["name"]
            if b["action"] == "PRESERVE":
                log.info("decom.preserve", type="GCS", name=name)
                continue
                
            if dry_run:
                log.info("decom.destroy_dry_run", type="GCS", name=name)
            else:
                log.info("decom.destroying", type="GCS", name=name)
                # gcloud storage rm -r gs://NAME
                cmd = ["storage", "rm", "-r", f"gs://{name}", "--project", self.project_id, "--quiet"]
                try:
                    subprocess.run(["gcloud"] + cmd, check=True, stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError as e:
                    log.error("decom.destroy_failed", name=name, error=str(e))

        # Networking
        for f in report["forwarding_rules"]:
            name = f["name"]
            reg = f["region"]
            if dry_run:
                log.info("decom.destroy_dry_run", type="FWD_RULE", name=name)
            else:
                log.info("decom.destroying", type="FWD_RULE", name=name)
                cmd = ["compute", "forwarding-rules", "delete", name, "--project", self.project_id, "--quiet"]
                if reg: cmd.extend(["--region", reg])
                else: cmd.append("--global")
                try:
                    subprocess.run(["gcloud"] + cmd, check=True, stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError as e:
                    log.error("decom.destroy_failed", name=name, error=str(e))
