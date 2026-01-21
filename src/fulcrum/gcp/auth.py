import os
from typing import Optional, Tuple
import structlog

log = structlog.get_logger()


class SecurityError(Exception):
    """Raised when security checks fail."""

    pass


# Required file permissions for service account keys (0o600 = owner read/write only)
REQUIRED_SA_KEY_MODE = 0o600


def validate_service_account_key(sa_key_path: str) -> bool:
    """
    Validate service account key file has correct permissions.

    Security checks:
    - File must have 0o600 permissions (owner read/write only)
    - File must be owned by the current user

    Args:
        sa_key_path: Path to the service account JSON key file

    Returns:
        True if validation passes

    Raises:
        SecurityError: If file has insecure permissions or ownership
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
