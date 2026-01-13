import os
from typing import Optional, Tuple

def load_credentials(sa_key_path: Optional[str] = None, scopes: Optional[list] = None):
    scopes = scopes or [
        "https://www.googleapis.com/auth/cloud-platform",
    ]
    if sa_key_path and os.path.exists(sa_key_path):
        from google.oauth2.service_account import Credentials as SACredentials
        creds = SACredentials.from_service_account_file(sa_key_path, scopes=scopes)
        project_id = creds.project_id
        return creds, project_id
    # Fallback to ADC
    import google.auth
    creds, project_id = google.auth.default(scopes=scopes)
    return creds, project_id

def load_impersonated_credentials(base_creds, target_service_account: str, scopes: Optional[list] = None):
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

def preflight_permission_check(compute_client, project_id: str) -> Tuple[bool, Optional[str]]:
    attempts = 0
    while attempts < 3:
        try:
            req = compute_client.zones().list(project=project_id)
            req.execute(num_retries=1)
            return True, None
        except Exception as e:
            msg = str(e)
            if "permission" in msg.lower() or "403" in msg:
                return False, "Missing roles (compute.viewer). Please grant least-privilege viewer roles."
            attempts += 1
    return False, "Preflight failed"
