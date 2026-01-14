from typing import Dict, List

from .mapping import map_check_id
from .models import CanonicalFinding, RawProwlerFinding, Severity, Status, Framework


def to_canonical(items: List[Dict]) -> List[CanonicalFinding]:
    """
    Normalize raw Prowler findings to canonical form using Pydantic models.

    Args:
        items: List of raw finding dictionaries from Prowler JSON/CSV

    Returns:
        List of typed CanonicalFinding models
    """
    out: List[CanonicalFinding] = []
    for it in items:
        # Use Pydantic model for flexible field handling
        raw = RawProwlerFinding(**it)

        check_id = raw.get_check_id()
        service = raw.get_service()
        status_raw = raw.get_status()
        severity_raw = raw.get_severity()
        resource_id = raw.get_resource_id()
        project_id = raw.get_project_id()

        # Map check ID to framework metadata
        mapped = map_check_id(str(check_id))

        # Normalize status to enum
        status = Status.UNKNOWN
        status_lower = status_raw.lower() if status_raw else ""
        if status_lower in ("fail", "failing", "failed"):
            status = Status.FAIL
        elif status_lower in ("pass", "passing", "passed"):
            status = Status.PASS
        elif status_lower in ("warning", "warn"):
            status = Status.WARNING

        # Normalize severity to enum
        severity = Severity.INFORMATIONAL
        severity_lower = severity_raw.lower() if severity_raw else ""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFORMATIONAL,
        }
        if severity_lower in severity_map:
            severity = severity_map[severity_lower]

        # Use mapped severity as fallback
        if not severity_raw and mapped.get("severity"):
            severity_map_fallback = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            mapped_severity = mapped.get("severity", "").lower()
            if mapped_severity in severity_map_fallback:
                severity = severity_map_fallback[mapped_severity]

        # Get framework, defaulting to UNKNOWN for invalid values
        framework = Framework.UNKNOWN
        mapped_framework = mapped.get("framework")
        if mapped_framework:
            try:
                framework = Framework(mapped_framework)
            except ValueError:
                # Unknown framework, keep as UNKNOWN
                pass

        # Create typed model
        finding = CanonicalFinding(
            project_id=str(project_id),
            resource_id=str(resource_id),
            check_id=str(check_id),
            service=str(service),
            status=status,
            severity=severity,
            framework=framework,
            description=raw.get_description(),
            recommendation=raw.get_remediation(),
            category=raw.get_category() or mapped.get("framework", ""),
            evidence=raw.get_evidence(),
        )
        out.append(finding)

    return out
