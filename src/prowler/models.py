"""
Pydantic Models for Security Findings.

Provides type-safe data models for:
- CanonicalFindings: Normalized security findings
- RawProwlerFinding: Raw Prowler JSON/CSV output
- FrameworkMapping: Check ID to framework mapping

Benefits:
- Validation at data ingestion points
- Type-safe attribute access (no more .get() calls)
- IDE autocomplete and type hints
- Serialization/deserialization support
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Status(str, Enum):
    """Status of a security finding."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    UNKNOWN = "UNKNOWN"


class Framework(str, Enum):
    """Security framework identifiers."""

    CIS = "cis"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    SOC2 = "soc2"
    PCI = "pci"
    NIST = "nist"
    ISO27001 = "iso27001"
    UNKNOWN = "unknown"


class CanonicalFinding(BaseModel):
    """
    Normalized security finding model.

    This is the canonical form used throughout the application after
    normalization from various input formats (JSON, CSV, API).
    """

    project_id: str = Field(..., description="GCP project ID")
    resource_id: str = Field(..., description="Unique identifier for the resource")
    check_id: str = Field(..., description="Prowler check identifier")
    service: str = Field(..., description="GCP service name (e.g., compute, storage)")
    status: Status = Field(default=Status.UNKNOWN, description="Finding status")
    severity: Severity = Field(
        default=Severity.INFORMATIONAL, description="Severity level"
    )
    framework: Framework = Field(
        default=Framework.UNKNOWN, description="Associated security framework"
    )
    description: str = Field(default="", description="Finding description")
    recommendation: str = Field(default="", description="Remediation recommendation")
    category: str = Field(default="", description="Category of the finding")
    evidence: str = Field(default="", description="Evidence supporting the finding")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

    model_config = ConfigDict(use_enum_values=True)

    @field_validator("project_id", "resource_id", "check_id", "service")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        if not v:
            return ""
        return v


class RawProwlerFinding(BaseModel):
    """
    Raw Prowler finding from JSON or CSV output.

    Prowler outputs findings in various formats with different field names.
    This model accepts multiple field name variations and normalizes them.
    """

    # Flexible field names with optional types (Prowler uses different casings)
    check_id: Optional[str] = None
    control_id: Optional[str] = None
    check_id_alt: Optional[str] = None  # CheckID

    service: Optional[str] = None
    service_alt: Optional[str] = None  # Service

    status: Optional[str] = None
    status_alt: Optional[str] = None  # Status
    result: Optional[str] = None

    severity: Optional[str] = None
    severity_alt: Optional[str] = None  # Severity

    resource_id: Optional[str] = None
    resource_id_alt: Optional[str] = None  # ResourceId, Resource

    project_id: Optional[str] = None
    project_id_alt: Optional[str] = None  # ProjectID

    description: Optional[str] = None
    description_alt: Optional[str] = None  # Description

    remediation: Optional[str] = None
    remediation_alt: Optional[str] = None  # Recommendation

    category: Optional[str] = None
    category_alt: Optional[str] = None  # Category

    evidence: Optional[str] = None
    evidence_alt: Optional[str] = None  # Evidence

    # Additional fields that may be present
    region: Optional[str] = None
    account: Optional[str] = None
    namespace: Optional[str] = None
    resource_name: Optional[str] = None
    resource_status: Optional[str] = None
    compliance: Optional[str] = None
    notes: Optional[str] = None

    model_config = ConfigDict(
        extra="allow"
    )  # Allow additional fields from Prowler output

    def get_check_id(self) -> str:
        """Get check ID with fallback logic."""
        return self.check_id or self.control_id or self.check_id_alt or ""

    def get_service(self) -> str:
        """Get service name with fallback logic."""
        return self.service or self.service_alt or ""

    def get_status(self) -> str:
        """Get status with fallback logic."""
        return self.status or self.status_alt or self.result or ""

    def get_severity(self) -> str:
        """Get severity with fallback logic."""
        return self.severity or self.severity_alt or ""

    def get_resource_id(self) -> str:
        """Get resource ID with fallback logic."""
        return self.resource_id or self.resource_id_alt or self.resource_name or ""

    def get_project_id(self) -> str:
        """Get project ID with fallback logic."""
        return self.project_id or self.project_id_alt or self.account or ""

    def get_description(self) -> str:
        """Get description with fallback logic."""
        return self.description or self.description_alt or ""

    def get_remediation(self) -> str:
        """Get remediation with fallback logic."""
        return self.remediation or self.remediation_alt or ""

    def get_category(self) -> str:
        """Get category with fallback logic."""
        return self.category or self.category_alt or ""

    def get_evidence(self) -> str:
        """Get evidence with fallback logic."""
        return self.evidence or self.evidence_alt or ""

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary with normalized keys."""
        return {
            "check_id": self.get_check_id(),
            "service": self.get_service(),
            "status": self.get_status(),
            "severity": self.get_severity(),
            "resource_id": self.get_resource_id(),
            "project_id": self.get_project_id(),
            "description": self.get_description(),
            "remediation": self.get_remediation(),
            "category": self.get_category(),
            "evidence": self.get_evidence(),
        }


class FrameworkMapping(BaseModel):
    """Mapping from check ID to security framework metadata."""

    check_id: str
    framework: Framework
    severity: Severity
    category: str
    name: str
    description: str


class FindingStats(BaseModel):
    """Statistics about security findings for reporting."""

    total: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)
    by_service: Dict[str, int] = Field(default_factory=dict)
    by_framework: Dict[str, int] = Field(default_factory=dict)
    failed_count: int = 0
    passed_count: int = 0

    @classmethod
    def from_findings(cls, findings: List[CanonicalFinding]) -> "FindingStats":
        """Calculate stats from a list of findings."""
        stats = cls()
        stats.total = len(findings)

        for f in findings:
            # Count by severity
            stats.by_severity[f.severity] = stats.by_severity.get(f.severity, 0) + 1

            # Count by status
            stats.by_status[f.status] = stats.by_status.get(f.status, 0) + 1

            # Count by service
            stats.by_service[f.service] = stats.by_service.get(f.service, 0) + 1

            # Count by framework
            stats.by_framework[f.framework] = stats.by_framework.get(f.framework, 0) + 1

            # Count pass/fail
            if f.status == Status.FAIL:
                stats.failed_count += 1
            elif f.status == Status.PASS:
                stats.passed_count += 1

        return stats
