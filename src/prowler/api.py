import json
from typing import List, Optional, Dict

class ProwlerUnavailable(Exception):
    pass

def is_api_available(base_url: str, token: Optional[str] = None) -> bool:
    try:
        import requests
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = requests.get(base_url.rstrip("/") + "/api/v1/docs", headers=headers, timeout=5)
        return r.status_code == 200
    except Exception:
        return False

def run_scan_api(base_url: str, token: Optional[str], provider: str, projects: List[str], org_id: Optional[str]) -> Dict[str, str]:
    try:
        import requests
        headers = {"Authorization": f"Bearer {token}"} if token else {"Content-Type": "application/json"}
        payload = {"provider": provider, "projects": projects, "org_id": org_id}
        start = requests.post(base_url.rstrip("/") + "/api/v1/scan", headers=headers, data=json.dumps(payload), timeout=10)
        if start.status_code != 200:
            raise ProwlerUnavailable(f"API scan start failed: {start.status_code}")
        job = start.json().get("job_id")
        if not job:
            raise ProwlerUnavailable("API did not return job_id")
        # Fetch results
        res = requests.get(base_url.rstrip("/") + f"/api/v1/results/{job}", headers=headers, timeout=30)
        if res.status_code != 200:
            raise ProwlerUnavailable(f"API results fetch failed: {res.status_code}")
        return {"job_id": job, "results": res.text}
    except Exception as e:
        raise ProwlerUnavailable(str(e))

