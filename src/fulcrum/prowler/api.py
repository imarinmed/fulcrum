import json
import os
from typing import List, Optional, Dict
import structlog

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = structlog.get_logger()


class ProwlerUnavailable(Exception):
    pass


def _create_secure_session() -> "requests.Session":
    """
    Create requests session with proper SSL and retry configuration.

    Security features:
    - SSL verification enabled by default
    - Custom CA bundle support
    - Retry strategy for resilience

    Returns:
        Configured requests Session object
    """
    import requests

    session = requests.Session()

    # Configure SSL verification
    verify_ssl = os.environ.get("FULCRUM_VERIFY_SSL", "true").lower() == "true"

    # Set up retry strategy for transient failures
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Set SSL verification
    session.verify = verify_ssl

    # Set custom CA bundle if provided
    ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle:
        session.verify = ca_bundle

    return session


def _mask_token(token: Optional[str]) -> str:
    """
    Mask token for logging, showing only first and last 8 characters.

    Args:
        token: Token to mask

    Returns:
        Masked token string
    """
    if not token:
        return "(none)"
    if len(token) <= 16:
        return "*" * len(token)
    return token[:8] + "*" * (len(token) - 16) + token[-8:]


def is_api_available(base_url: str, token: Optional[str] = None) -> bool:
    try:
        import requests

        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = requests.get(
            base_url.rstrip("/") + "/api/v1/docs", headers=headers, timeout=5
        )
        return r.status_code == 200
    except (ImportError, requests.RequestException) as e:
        log.warning(
            "prowler.api_check_failed",
            url=base_url,
            token_masked=_mask_token(token),
            error=str(e),
            security_event=True,
        )
        return False


def run_scan_api(
    base_url: str,
    token: Optional[str],
    provider: str,
    projects: List[str],
    org_id: Optional[str],
) -> Dict[str, str]:
    try:
        import requests

        session = _create_secure_session()

        # Prepare headers (token masked in logs)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        payload = {"provider": provider, "projects": projects, "org_id": org_id}

        log.info(
            "prowler.scan_starting",
            url=base_url,
            projects=projects,
            token_masked=_mask_token(token),
            security_event=True,
        )

        start = session.post(
            base_url.rstrip("/") + "/api/v1/scan",
            headers=headers,
            data=json.dumps(payload),
            timeout=10,
        )

        if start.status_code != 200:
            raise ProwlerUnavailable(f"API scan start failed: {start.status_code}")

        job = start.json().get("job_id")
        if not job:
            raise ProwlerUnavailable("API did not return job_id")

        # Fetch results
        res = session.get(
            base_url.rstrip("/") + f"/api/v1/results/{job}", headers=headers, timeout=30
        )

        if res.status_code != 200:
            raise ProwlerUnavailable(f"API results fetch failed: {res.status_code}")

        log.info(
            "prowler.scan_complete",
            job_id=job,
            token_masked=_mask_token(token),
            security_event=True,
        )

        return {"job_id": job, "results": res.text}
    except (ImportError, requests.RequestException) as e:
        log.error(
            "prowler.scan_failed",
            url=base_url,
            token_masked=_mask_token(token),
            error=str(e),
            security_event=True,
        )
        raise ProwlerUnavailable(str(e))
