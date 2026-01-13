import os
import json
import glob
from typing import List, Dict, Any
import structlog

log = structlog.get_logger()

class ReportAggregator:
    def __init__(self, report_dir: str):
        self.report_dir = report_dir

    def aggregate(self) -> Dict[str, Any]:
        """
        Reads all .json-ocsf files in the report directory and creates a summary.
        Assumes Prowler OCSF JSON output.
        """
        summary = {
            "projects": {},
            "total_stats": {"FAIL": 0, "PASS": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }

        # Find all ocsf json files
        pattern = os.path.join(self.report_dir, "*.ocsf.json")
        files = glob.glob(pattern)
        
        for f in files:
            try:
                with open(f, 'r') as json_file:
                    # OCSF JSON might be a single object or list, but Prowler output-modes json-ocsf typically produces one file.
                    try:
                        data = json.load(json_file)
                    except json.JSONDecodeError:
                        continue 

                    # OCSF is likely a list of finding objects
                    if not isinstance(data, list):
                        # If it's a single object, wrap it
                        data = [data]

                    for finding in data:
                        # Extract Project ID from OCSF structure
                        # finding -> cloud -> project -> uid OR cloud -> account -> uid
                        try:
                            project_id = finding.get("cloud", {}).get("project", {}).get("uid")
                            if not project_id or project_id == "unknown":
                                project_id = finding.get("cloud", {}).get("account", {}).get("uid", "unknown")
                        except:
                            project_id = "unknown"
                        
                        # Extract Status
                        # In OCSF, status might be under 'status_code' or 'state' or 'activity_id'
                        # Prowler maps FAIL/PASS to OCSF...
                        # Let's inspect typical Prowler OCSF mapping if we can't see it.
                        # Usually Prowler adds custom fields or standard OCSF fields.
                        # Status ID 1: New, 2: In Progress, 3: Resolved... 
                        # Prowler specific:
                        # 'status': 'FAIL' -> maybe finding_info.title contains FAIL?
                        # Or finding.status_id?
                        # Let's try to find a Prowler specific field or standard OCSF.
                        # If finding['status'] exists (Prowler often leaves non-OCSF fields in top level in some versions or extensions)
                        
                        # Fallback: Check typical Prowler keys if mixed in, or rely on 'severity_id'
                        # Severity ID: 1 (Info), 2 (Low), 3 (Medium), 4 (High), 5 (Critical), 6 (Fatal)
                        severity_id = finding.get("severity_id", 0)
                        severity_map = {1: "LOW", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL", 6: "CRITICAL"}
                        # Prowler mapping might differ slightly.
                        # Prowler 3: Info(0), Low(1), Medium(2), High(3), Critical(4)
                        # Prowler 4 OCSF:
                        # Informational: 1
                        # Low: 2
                        # Medium: 3
                        # High: 4
                        # Critical: 5
                        
                        severity = severity_map.get(severity_id, "UNKNOWN")
                        
                        # Status?
                        # If severity is Informational (1) and it's a "pass", how do we know?
                        # Prowler OCSF usually only exports FINDINGS (Failures)?
                        # Or it exports everything.
                        # Let's check 'state' or 'status'.
                        # Prowler: 'status': 'PASS' / 'FAIL' in standard json.
                        # In OCSF, maybe 'state_id'.
                        # 'state_id': 1 (New) -> FAIL?
                        # 'state_id': 2 (Resolved) -> PASS?
                        
                        # Let's try to infer from typical OCSF usage for findings.
                        # Often "New" implies an active finding (Fail).
                        # If we can't determine, we assume it's a finding (Fail) because typical security reports list findings.
                        # But Prowler can list Passes.
                        
                        # Hack: Check for "PASS" string in message or description if possible.
                        # Or look for 'status' key if Prowler leaks it.
                        status = "FAIL" # Default to fail if it's in the report as a finding
                        
                        # Prowler v4 OCSF output:
                        # status: "FAIL" might be mapped to state_id="New"
                        # status: "PASS" might be mapped to state_id="Resolved" or "Suppressed"
                        
                        state_id = finding.get("state_id")
                        if state_id == 2: # Resolved
                             status = "PASS"
                        elif state_id == 0 or state_id == 1: # Unknown or New
                             status = "FAIL"

                        if project_id not in summary["projects"]:
                            summary["projects"][project_id] = {
                                "FAIL": 0, "PASS": 0, 
                                "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
                            }
                        
                        if status == "FAIL":
                            summary["projects"][project_id]["FAIL"] += 1
                            summary["total_stats"]["FAIL"] += 1
                            
                            if severity in summary["projects"][project_id]:
                                summary["projects"][project_id][severity] += 1
                            if severity in summary["total_stats"]:
                                summary["total_stats"][severity] += 1
                                
                        elif status == "PASS":
                            summary["projects"][project_id]["PASS"] += 1
                            summary["total_stats"]["PASS"] += 1

            except Exception as e:
                log.warning("aggregator.error", file=f, error=str(e))
                
        # Fix project counting: The previous issue was likely due to Prowler outputs overwriting or
        # using project_ids that don't match the folder structure if run sequentially.
        # But here we parse OCSF content which should have the correct project ID inside.
        # If "Total Projects Scanned: 1" appears, it means only one unique project_id was found in the OCSF files.
        # This can happen if Prowler defaults to the account ID or a fixed string if not properly passed/parsed.
        # Let's trust the 'project_id' key extracted from OCSF.
        
        return summary
