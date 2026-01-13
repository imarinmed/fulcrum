import subprocess
import json
import structlog
from typing import List, Dict, Any, Optional

log = structlog.get_logger()

class ProwlerUnavailable(Exception):
    pass

def list_checks(provider: str = "gcp") -> List[str]:
    """List available prowler checks for a provider."""
    try:
        # prowler <provider> --list-checks
        # Using default prowler path if in PATH, or specify full path
        prowler_cmd = "prowler"
        # If running in environment where prowler is in ~/.local/bin
        import os
        if os.path.exists(os.path.expanduser("~/.local/bin/prowler")):
            prowler_cmd = os.path.expanduser("~/.local/bin/prowler")
            
        cmd = [prowler_cmd, provider, "--list-checks"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise ProwlerUnavailable(f"Prowler list failed: {res.stderr}")
        
        # Output is text, we need to parse. Or just trust user to know checks.
        # This is just a helper.
        return res.stdout.splitlines()
    except FileNotFoundError:
        raise ProwlerUnavailable("Prowler executable not found.")

def run_scan(
    project_id: str, 
    checks: Optional[List[str]] = None, 
    output_format: str = "json"
) -> str:
    """
    Run prowler scan on a GCP project.
    Returns the path to the output file.
    """
    prowler_cmd = "prowler"
    import os
    if os.path.exists(os.path.expanduser("~/.local/bin/prowler")):
        prowler_cmd = os.path.expanduser("~/.local/bin/prowler")

    # prowler gcp --project-ids PROJECT --checks ...
    cmd = [prowler_cmd, "gcp", "--project-ids", project_id]
    
    if checks:
        cmd.extend(["--checks"] + checks)
    
    # We want to output to a specific file/format
    # Prowler writes to output directory by default.
    # We can control output directory.
    cmd.extend(["--output-directory", "prowler_reports"])
    # We want json output - Prowler v4+ uses json-ocsf or json-asff
    cmd.extend(["--output-modes", "json-ocsf"])

    log.info("prowler.scan_start", project=project_id)
    try:
        # This can take a while, so we run blocking for now (CLI tool).
        subprocess.run(cmd, check=True)
        # Prowler generates a filename with timestamp. We need to find it?
        # Or we can return the directory.
        return "prowler_reports"
    except subprocess.CalledProcessError as e:
        log.error("prowler.scan_failed", error=str(e))
        raise
    except FileNotFoundError:
        raise ProwlerUnavailable("Prowler executable not found.")
