from typing import Any, Dict, List
from ..core.remediation import RemediationAction, RemediationResult
from .runner import run_gcloud_json
import structlog

log = structlog.get_logger()

class GKEReadOnlyPortRemediation(RemediationAction):
    @property
    def id(self) -> str:
        # Using a canonical ID that matches Prowler's check ID if possible
        return "cis_gke_v1_6_0_4_2_4" 

    @property
    def description(self) -> str:
        return "Disable insecure kubelet read-only port 10255 on GKE clusters."

    def execute(self, target: Any, dry_run: bool = False) -> RemediationResult:
        # target can be a dict with project_id, cluster_name, and location
        project_id = target.get("project_id")
        cluster_name = target.get("cluster_name")
        location = target.get("location") or target.get("region") or target.get("zone")

        if not project_id or not cluster_name or not location:
             return RemediationResult(self.id, False, f"Missing required target info: {target}")

        cmd = [
            "container", "clusters", "update", cluster_name,
            "--project", project_id,
            "--location", location,
            "--no-enable-insecure-kubelet-readonly-port"
        ]

        if dry_run:
            log.info("remediation.dry_run", command=" ".join(cmd))
            return RemediationResult(self.id, True, f"Dry run: Would execute: gcloud {' '.join(cmd)}")

        try:
            # Note: update command might print to stderr/stdout and not return JSON in a clean way
            # unless --format=json is used. run_gcloud_json adds --format=json.
            res = run_gcloud_json(cmd)
            return RemediationResult(self.id, True, "Successfully disabled insecure port", changes=res)
        except Exception as e:
            return RemediationResult(self.id, False, f"Failed to update cluster: {str(e)}")
