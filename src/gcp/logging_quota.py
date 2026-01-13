import json
from typing import Dict, List, Any
import structlog
from .runner import run_gcloud_json, GCloudError

log = structlog.get_logger()

class LoggingQuotaAnalyzer:
    def __init__(self, project_id: str):
        self.project_id = project_id

    def get_logging_metrics(self) -> Dict[str, Any]:
        """
        Retrieves logging usage metrics.
        Note: Precise cost analysis requires Billing API which might be restricted.
        We will look at:
        1. Log Bucket configurations (retention, etc.)
        2. Log Sink configurations (exclusions)
        3. Recent ingestion volume (if available via metrics)
        """
        report = {
            "project_id": self.project_id,
            "buckets": [],
            "sinks": [],
            "exclusions": []
        }

        # 1. List Buckets
        try:
            # buckets are usually regional e.g. locations/global/buckets/default
            # or locations/europe-west1/buckets/...
            # We list from parent project
            buckets = run_gcloud_json([
                "logging", "buckets", "list",
                "--project", self.project_id
            ])
            for b in buckets:
                report["buckets"].append({
                    "name": b.get("name"),
                    "retentionDays": b.get("retentionDays"),
                    "lifecycleState": b.get("lifecycleState"),
                    "locked": b.get("locked", False)
                })
        except GCloudError as e:
            log.error("logging.buckets_list_failed", error=str(e))

        # 2. List Sinks
        try:
            sinks = run_gcloud_json([
                "logging", "sinks", "list",
                "--project", self.project_id
            ])
            for s in sinks:
                report["sinks"].append({
                    "name": s.get("name"),
                    "destination": s.get("destination"),
                    "filter": s.get("filter"),
                    "disabled": s.get("disabled", False)
                })
        except GCloudError as e:
            log.error("logging.sinks_list_failed", error=str(e))

        # 3. Check Monitoring Metrics for Ingestion
        # metric: logging.googleapis.com/byte_count
        # We try to fetch last 24h count
        # This requires monitoring.read scope
        
        return report

def analyze_project(project_id: str) -> Dict[str, Any]:
    analyzer = LoggingQuotaAnalyzer(project_id)
    return analyzer.get_logging_metrics()
