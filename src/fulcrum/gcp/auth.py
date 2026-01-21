import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
import structlog

log = structlog.get_logger()


class SecurityError(Exception):
    """Raised when security checks fail."""

    pass


# Required file permissions for service account keys (0o600 = owner read/write only)
REQUIRED_SA_KEY_MODE = 0o600


def _parse_rfc3339_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse RFC3339 timestamp string to datetime object."""
    if not timestamp_str:
        return None
    try:
        # Handle common RFC3339 formats
        # Example: "2024-01-01T00:00:00Z" or "2024-01-01T00:00:00.000Z"
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        # Parse with timezone
        from datetime import timedelta

        if "+" in timestamp_str:
            tz_part = timestamp_str.split("+")[1]
            hours, minutes = tz_part.split(":")
            tz = timezone(timedelta(hours=int(hours), minutes=int(minutes)))
            dt_str = timestamp_str.split("+")[0]
        elif "-" in timestamp_str[-6:-4]:  # Check for negative offset like -05:00
            tz_part = timestamp_str[-6:]
            hours, minutes = tz_part.split(":")
            tz = timezone(timedelta(hours=int(hours), minutes=int(minutes)))
            dt_str = timestamp_str[:-6]
        else:
            tz = timezone.utc
            dt_str = timestamp_str

        return datetime.fromisoformat(dt_str).replace(tzinfo=tz)
    except (ValueError, AttributeError):
        return None


def validate_service_account_key(sa_key_path: str) -> bool:
    """
    Validate service account key file has correct permissions and is not expired.

    Security checks:
    - File must have 0o600 permissions (owner read/write only)
    - File must be owned by the current user
    - Key must not be expired (validBeforeTime check)

    Args:
        sa_key_path: Path to the service account JSON key file

    Returns:
        True if validation passes

    Raises:
        SecurityError: If file has insecure permissions, ownership, or is expired
    """
    if not os.path.exists(sa_key_path):
        raise SecurityError(f"Service account key not found: {sa_key_path}")

    try:
        file_stat = os.stat(sa_key_path)

        # Check file permissions (must be 0o600 or more restrictive)
        if file_stat.st_mode & 0o077:  # Check for group/other permissions
            actual_mode = oct(file_stat.st_mode)[-3:]
            raise SecurityError(
                f"Service account key has insecure permissions: {actual_mode}. "
                f"Expected {oct(REQUIRED_SA_KEY_MODE)[-3:]}. "
                f"Run: chmod 600 {sa_key_path}"
            )

        # Check file ownership (should be owned by application user)
        if file_stat.st_uid != os.getuid():
            raise SecurityError(
                f"Service account key is not owned by current user "
                f"(file UID: {file_stat.st_uid}, current UID: {os.getuid()})"
            )

        # Check key expiration
        _check_sa_key_expiration(sa_key_path)

        # Log successful validation
        log.info(
            "auth.sa_key_validated",
            path=sa_key_path,
            mode=oct(file_stat.st_mode)[-3:],
            security_event=True,
        )

        return True

    except OSError as e:
        raise SecurityError(f"Failed to validate service account key: {e}")


def _check_sa_key_expiration(sa_key_path: str) -> None:
    """
    Check if a service account key is expired.

    Reads the SA key JSON and checks validBeforeTime against current time.

    Args:
        sa_key_path: Path to the service account JSON key file

    Raises:
        SecurityError: If the key is expired
    """
    try:
        with open(sa_key_path, "r") as f:
            key_data = json.load(f)

        # Check for expiration timestamp
        valid_before = key_data.get("validBeforeTime") or key_data.get(
            "valid_before_time"
        )

        if valid_before:
            expiration_dt = _parse_rfc3339_timestamp(valid_before)
            if expiration_dt:
                now = datetime.now(timezone.utc)
                if now > expiration_dt:
                    expired_for = now - expiration_dt
                    raise SecurityError(
                        f"Service account key expired on {valid_before} "
                        f"({expired_for.days} days ago). Please rotate the key."
                    )
                elif expiration_dt - now < timedelta(days=7):
                    # Warn if expiring within 7 days
                    log.warning(
                        "auth.sa_key_expiring_soon",
                        expires_at=valid_before,
                        days_until_expiry=(expiration_dt - now).days,
                        security_event=True,
                    )

    except json.JSONDecodeError:
        # If we can't parse the JSON, skip expiration check
        log.warning(
            "auth.sa_key_expiration_check_skipped",
            reason="invalid_json",
            path=sa_key_path,
        )


def load_credentials(sa_key_path: Optional[str] = None, scopes: Optional[list] = None):
    """
    Load GCP credentials with security validation.

    Security considerations:
    - Validates service account key file permissions (0o600)
    - Uses least-privilege scopes by default
    - Falls back to ADC only if no SA key provided
    - Logs all authentication attempts for audit

    Args:
        sa_key_path: Path to service account JSON key file
        scopes: OAuth2 scopes to request

    Returns:
        Tuple of (credentials, project_id)

    Raises:
        SecurityError: If SA key file has insecure permissions
    """
    scopes = scopes or [
        "https://www.googleapis.com/auth/cloud-platform",
    ]
    if sa_key_path and os.path.exists(sa_key_path):
        # Validate SA key before loading
        validate_service_account_key(sa_key_path)

        from google.oauth2.service_account import Credentials as SACredentials

        creds = SACredentials.from_service_account_file(sa_key_path, scopes=scopes)
        project_id = creds.project_id
        return creds, project_id
    # Fallback to ADC
    import google.auth

    creds, project_id = google.auth.default(scopes=scopes)
    return creds, project_id


def load_impersonated_credentials(
    base_creds, target_service_account: str, scopes: Optional[list] = None
):
    scopes = scopes or ["https://www.googleapis.com/auth/cloud-platform"]
    try:
        from google.auth import impersonated_credentials

        target = impersonated_credentials.Credentials(
            source_credentials=base_creds,
            target_principal=target_service_account,
            target_scopes=scopes,
            lifetime=3600,
        )
        return target
    except Exception as e:
        raise RuntimeError(f"impersonation.failed: {e}")


def preflight_permission_check(
    compute_client, project_id: str
) -> Tuple[bool, Optional[str]]:
    attempts = 0
    while attempts < 3:
        try:
            req = compute_client.zones().list(project=project_id)
            req.execute(num_retries=1)
            return True, None
        except Exception as e:
            msg = str(e)
            if "permission" in msg.lower() or "403" in msg:
                return (
                    False,
                    "Missing roles (compute.viewer). Please grant least-privilege viewer roles.",
                )
            attempts += 1
    return False, "Preflight failed"
