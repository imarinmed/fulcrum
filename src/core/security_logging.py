"""
Security audit logging module.

Provides isolated logging for security events with:
- Separate security logger
- Security event tagging
- Audit trail generation
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import structlog
import json

# Create dedicated security logger
security_logger = structlog.get_logger("security")

# Audit trail file path
AUDIT_LOG_PATH = Path(
    os.environ.get("FULCRUM_AUDIT_LOG", Path.home() / ".fulcrum" / "audit.log")
)


def log_security_event(
    event: str,
    severity: str = "INFO",
    actor: str = "system",
    action: str = "",
    target: str = "",
    result: str = "success",
    metadata: Optional[Dict[str, Any]] = None,
    write_to_audit: bool = True,
) -> None:
    """
    Log a security event to both structured logs and audit trail.

    Args:
        event: Event type/name
        severity: Event severity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        actor: User or system performing the action
        action: Action being performed
        target: Target of the action
        result: Result of the action
        metadata: Additional metadata
        write_to_audit: Whether to write to persistent audit trail
    """
    event_data = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "event": event,
        "severity": severity,
        "actor": actor,
        "action": action,
        "target": target,
        "result": result,
        "metadata": metadata or {},
    }

    # Log to structured logger
    security_logger.info(event, **event_data, security_event=True)

    # Write to persistent audit trail
    if write_to_audit:
        _write_audit_entry(event_data)


def _write_audit_entry(entry: Dict[str, Any]) -> None:
    """
    Write entry to audit trail file.

    Args:
        entry: Audit entry dictionary
    """
    try:
        # Ensure audit directory exists
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")

    except (OSError, IOError) as e:
        # Fall back to main logger if audit write fails
        security_logger.error(
            "audit.write_failed", path=str(AUDIT_LOG_PATH), error=str(e)
        )


def log_authentication(
    success: bool, method: str, actor: str = "", error: Optional[str] = None
) -> None:
    """
    Log authentication event.

    Args:
        success: Whether authentication succeeded
        method: Authentication method used
        actor: User attempting authentication
        error: Error message if failed
    """
    log_security_event(
        event="authentication",
        severity="ERROR" if not success else "INFO",
        actor=actor,
        action=f"authenticate:{method}",
        result="success" if success else "failed",
        metadata={"error": error} if error else None,
    )


def log_config_change(action: str, config_path: str, actor: str = "system") -> None:
    """
    Log configuration change.

    Args:
        action: Change action (create, update, delete)
        config_path: Path to config file
        actor: User making the change
    """
    log_security_event(
        event="config_change",
        severity="WARNING",
        actor=actor,
        action=f"config:{action}",
        target=config_path,
    )


def log_decommission(
    action: str,
    project_id: str,
    resource_type: str,
    resource_name: str,
    actor: str = "system",
    dry_run: bool = False,
) -> None:
    """
    Log decommission operation.

    Args:
        action: Operation action
        project_id: GCP project ID
        resource_type: Resource type (GKE, SQL, Bucket, etc.)
        resource_name: Resource name
        actor: User performing operation
        dry_run: Whether this is a dry run
    """
    log_security_event(
        event="decommission",
        severity="CRITICAL",
        actor=actor,
        action=f"decommission:{action}",
        target=f"{project_id}/{resource_type}/{resource_name}",
        metadata={"dry_run": dry_run},
    )


def log_api_call(
    api_name: str,
    endpoint: str,
    success: bool,
    duration_ms: int,
    error: Optional[str] = None,
) -> None:
    """
    Log external API call.

    Args:
        api_name: Name of the API
        endpoint: API endpoint
        success: Whether call succeeded
        duration_ms: Call duration in milliseconds
        error: Error message if failed
    """
    log_security_event(
        event="api_call",
        severity="ERROR" if not success else "DEBUG",
        action=f"api:{api_name}",
        target=endpoint,
        result="success" if success else "failed",
        metadata={"duration_ms": duration_ms, "error": error}
        if error
        else {"duration_ms": duration_ms},
    )
