import subprocess
from typing import List, Any
import logging

logger = logging.getLogger(__name__)


class GCloudError(Exception):
    """Exception raised when a gcloud command fails."""

    pass


def run_gcloud(args: List[str], timeout: int = 60) -> Any:
    """
    Run a gcloud command and return parsed JSON output.

    Centralized gcloud execution logic that handles:
    - Command execution with timeout
    - Error logging
    - JSON output parsing
    - Structured error reporting

    Args:
        args: Command arguments to pass to gcloud (without 'gcloud' prefix)
        timeout: Command timeout in seconds (default: 60)

    Returns:
        Parsed JSON output from gcloud command

    Raises:
        GCloudError: If command times out, fails, or returns invalid JSON
    """
    cmd = ["gcloud"] + args + ["--format=json"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=timeout
        )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out after {timeout}s: {' '.join(cmd)}"
        logger.error(error_msg)
        raise GCloudError(error_msg)
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() if e.stderr else "Unknown error"
        full_msg = f"Command failed: {err_msg}"
        logger.error(full_msg)
        raise GCloudError(full_msg)
    except json.JSONDecodeError as e:
        error_msg = f"Failed to parse gcloud JSON output: {e}"
        logger.error(error_msg)
        raise GCloudError(error_msg)


# Keep backward compatibility alias
run_gcloud_json = run_gcloud
