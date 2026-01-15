import json
import subprocess
from typing import List, Any
import logging
import re
import structlog

from ..core.settings import load_settings

logger = logging.getLogger(__name__)
security_logger = structlog.get_logger("security")


class GCloudError(Exception):
    """Exception raised when a gcloud command fails."""

    pass


# Patterns that must not appear in command arguments
# These are checked only when not using shell=True, so we focus on
# actual command injection that could bypass subprocess safety
_DANGEROUS_PATTERNS = [
    r"\x00",  # Null bytes (always dangerous)
    r"\.\./",  # Path traversal (parent directory)
    r"\.\.\\",  # Path traversal (Windows parent directory)
]


def _validate_command_arg(arg: str) -> bool:
    """
    Validate a command argument for security.

    Args:
        arg: Argument to validate

    Returns:
        True if safe, raises ValueError if dangerous

    Raises:
        ValueError: If argument contains dangerous patterns
    """
    for pattern in _DANGEROUS_PATTERNS:
        if re.search(pattern, arg):
            raise ValueError(
                f"Potentially dangerous pattern '{pattern}' found in argument: {arg}"
            )
    return True


def run_gcloud(args: List[str], timeout: int = 60) -> Any:
    """
    Run a gcloud command and return parsed JSON output.

    Centralized gcloud execution logic that handles:
    - Command execution with timeout
    - Error logging
    - JSON output parsing
    - Structured error reporting
    - Input validation for security

    Args:
        args: Command arguments to pass to gcloud (without 'gcloud' prefix)
        timeout: Command timeout in seconds (default: 60)

    Returns:
        Parsed JSON output from gcloud command

    Raises:
        GCloudError: If command times out, fails, or returns invalid JSON
    """
    cmd = ["gcloud"] + args + ["--format=json"]

    # Validate all arguments before execution
    for arg in cmd:
        try:
            _validate_command_arg(arg)
        except ValueError as e:
            security_logger.error(
                "gcloud.invalid_argument",
                argument=arg,
                error=str(e),
                security_event=True,
            )
            raise GCloudError(str(e))

    security_logger.info(
        "gcloud.executing",
        command=" ".join(cmd[:3]) + " ...",  # Log first 3 args for brevity
        timeout=timeout,
        security_event=True,
    )

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=timeout
        )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out after {timeout}s"
        logger.error(error_msg)
        security_logger.warning(
            "gcloud.timeout", command=error_msg, timeout=timeout, security_event=True
        )
        raise GCloudError(error_msg)
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() if e.stderr else "Unknown error"
        full_msg = f"Command failed: {err_msg}"
        logger.error(full_msg)
        security_logger.error(
            "gcloud.command_failed",
            error=full_msg,
            return_code=e.returncode,
            security_event=True,
        )
        raise GCloudError(full_msg)
    except json.JSONDecodeError as e:
        error_msg = f"Failed to parse gcloud JSON output: {e}"
        logger.error(error_msg)
        security_logger.warning(
            "gcloud.json_parse_error", error=error_msg, security_event=True
        )
        raise GCloudError(error_msg)


# Keep backward compatibility alias
run_gcloud_json = run_gcloud
