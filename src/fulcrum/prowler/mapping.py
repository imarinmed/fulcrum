from typing import Dict

DEFAULT_MAPPING: Dict[str, Dict[str, str]] = {
    "gcp_iam_no_admin": {"framework": "LeastPrivilege", "severity": "high"},
    "gcp_storage_bucket_public": {"framework": "DataProtection", "severity": "high"},
    "gcp_compute_firewall_open": {"framework": "NetworkSecurity", "severity": "high"},
}

def map_check_id(check_id: str) -> Dict[str, str]:
    return DEFAULT_MAPPING.get(check_id, {"framework": "Unmapped", "severity": "medium"})

