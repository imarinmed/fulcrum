import subprocess
import json
import time
from typing import List, Any, Optional

class GCloudError(Exception):
    pass

def run_gcloud_json(args: List[str], timeout: int = 30) -> Any:
    """Run a gcloud command and return parsed JSON output with timeout."""
    cmd = ["gcloud"] + args + ["--format=json"]
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True,
            timeout=timeout
        )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        raise GCloudError(f"Command timed out after {timeout}s: {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        # Some commands might fail if resource doesn't exist (404), which is fine for audit.
        # But we need to distinguish.
        # For now, we raise custom error.
        err_msg = e.stderr.strip()
        raise GCloudError(f"Command failed: {err_msg}")
    except json.JSONDecodeError:
        raise GCloudError("Failed to parse gcloud JSON output")

