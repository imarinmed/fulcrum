from typing import Dict, List
from .mapping import map_check_id

def to_canonical(items: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    for it in items:
        check_id = it.get("check_id") or it.get("ControlId") or it.get("CheckID") or ""
        service = it.get("service") or it.get("Service") or ""
        status = it.get("status") or it.get("Status") or it.get("result") or ""
        severity = it.get("severity") or it.get("Severity") or ""
        resource_id = it.get("resource_id") or it.get("ResourceId") or it.get("Resource") or ""
        project_id = it.get("project_id") or it.get("ProjectID") or ""
        mapped = map_check_id(str(check_id))
        rec = {
            "project_id": str(project_id),
            "resource_id": str(resource_id),
            "check_id": str(check_id),
            "service": str(service),
            "status": str(status),
            "severity": str(severity or mapped.get("severity")),
            "framework": mapped.get("framework"),
            "description": str(it.get("description") or it.get("Description") or ""),
            "recommendation": str(it.get("remediation") or it.get("Recommendation") or ""),
            "category": str(it.get("category") or it.get("Category") or mapped.get("framework")),
            "evidence": str(it.get("evidence") or it.get("Evidence") or ""),
        }
        out.append(rec)
    return out

