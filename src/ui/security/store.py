"""
Security Data Store Extension.

Provides centralized security data management with:
- Security findings aggregation from multiple sources
- Compliance score calculations
- Security score computation
- Caching with TTL
- Reactive callbacks for UI updates
"""

import json
import glob
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Set
from enum import Enum
import structlog

from ..app import ViewState

log = structlog.get_logger()


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


@dataclass
class SecurityFinding:
    """A normalized security finding."""

    check_id: str
    service: str
    status: Status
    severity: Severity
    framework: Framework
    project_id: str
    resource_id: str
    description: str
    recommendation: str
    category: str
    evidence: str
    timestamp: str = ""
    file: Optional[str] = None
    line: Optional[int] = None
    match_snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "service": self.service,
            "status": self.status.value
            if isinstance(self.status, Status)
            else self.status,
            "severity": self.severity.value
            if isinstance(self.severity, Severity)
            else self.severity,
            "framework": self.framework.value
            if isinstance(self.framework, Framework)
            else self.framework,
            "project_id": self.project_id,
            "resource_id": self.resource_id,
            "description": self.description,
            "recommendation": self.recommendation,
            "category": self.category,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "file": self.file,
            "line": self.line,
            "match_snippet": self.match_snippet,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityFinding":
        """Create from dictionary."""
        return cls(
            check_id=data.get("check_id", ""),
            service=data.get("service", ""),
            status=Status(data.get("status", "UNKNOWN")),
            severity=Severity(data.get("severity", "informational")),
            framework=Framework(data.get("framework", "unknown")),
            project_id=data.get("project_id", ""),
            resource_id=data.get("resource_id", ""),
            description=data.get("description", ""),
            recommendation=data.get("recommendation", ""),
            category=data.get("category", ""),
            evidence=data.get("evidence", ""),
            timestamp=data.get("timestamp", ""),
            file=data.get("file"),
            line=data.get("line"),
            match_snippet=data.get("match_snippet"),
        )


@dataclass
class ComplianceScore:
    """Compliance score for a framework."""

    framework: Framework
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    compliance_percentage: float = 0.0

    @property
    def pass_rate(self) -> float:
        if self.total_checks == 0:
            return 0.0
        return (self.passed_checks / self.total_checks) * 100


@dataclass
class SecurityData:
    """Aggregated security data with metadata."""

    findings: List[SecurityFinding] = field(default_factory=list)
    compliance_scores: Dict[Framework, ComplianceScore] = field(default_factory=dict)
    security_score: int = 0
    risk_level: str = "UNKNOWN"
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    projects: Set[str] = field(default_factory=set)
    services: Set[str] = field(default_factory=set)
    last_updated: float = 0.0
    loaded_at: float = 0.0
    valid_for_seconds: int = 300  # 5 minutes TTL

    def is_valid(self) -> bool:
        """Check if data is still valid based on TTL."""
        return (time.time() - self.loaded_at) < self.valid_for_seconds


@dataclass
class FindingFilters:
    """Filters for security findings."""

    severities: Set[Severity] = field(default_factory=set)
    statuses: Set[Status] = field(default_factory=set)
    frameworks: Set[Framework] = field(default_factory=set)
    services: Set[str] = field(default_factory=set)
    projects: Set[str] = field(default_factory=set)
    search_query: str = ""
    show_only_failures: bool = False

    def matches(self, finding: SecurityFinding) -> bool:
        """Check if finding matches all active filters."""
        if self.severities and finding.severity not in self.severities:
            return False
        if self.statuses and finding.status not in self.statuses:
            return False
        if self.frameworks and finding.framework not in self.frameworks:
            return False
        if self.services and finding.service not in self.services:
            return False
        if self.projects and finding.project_id not in self.projects:
            return False
        if self.show_only_failures and finding.status == Status.PASS:
            return False
        if self.search_query:
            query = self.search_query.lower()
            search_text = f"{finding.description} {finding.check_id} {finding.service} {finding.resource_id}".lower()
            if query not in search_text:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert filters to dictionary for serialization."""
        return {
            "severities": [s.value for s in self.severities],
            "statuses": [s.value for s in self.statuses],
            "frameworks": [f.value for f in self.frameworks],
            "services": list(self.services),
            "projects": list(self.projects),
            "search_query": self.search_query,
            "show_only_failures": self.show_only_failures,
        }


class SecurityStore:
    """
    Centralized security data store with caching and aggregation.

    Provides:
    - Automatic caching of security data
    - TTL-based cache invalidation
    - Findings aggregation from multiple sources
    - Security score calculation
    - Compliance score computation
    - Reactive callbacks for UI updates
    """

    # Severity weights for security score calculation
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 15,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 1,
        Severity.INFORMATIONAL: 0,
    }

    # Risk level thresholds
    RISK_THRESHOLDS = {
        "CRITICAL": (0, 30),
        "HIGH": (31, 50),
        "MEDIUM": (51, 70),
        "LOW": (71, 85),
        "MINIMAL": (86, 100),
    }

    def __init__(self, out_dir: str):
        self.out_dir = out_dir
        self._cache: Dict[str, SecurityData] = {}
        self._callbacks: List[Callable] = []
        self._current_filters = FindingFilters()

    def register_callback(self, callback: Callable) -> None:
        """Register a callback to be called when data changes."""
        self._callbacks.append(callback)

    def _notify(self) -> None:
        """Notify all registered callbacks of data change."""
        for callback in self._callbacks:
            try:
                callback()
            except Exception as e:
                log.warning("ui.callback_error", error=str(e), security_event=True)

    def get_prowler_output_dir(self) -> str:
        """Get the Prowler output directory path."""
        return os.path.join(self.out_dir, "prowler_output")

    def get_security_audit_path(self) -> str:
        """Get the security audit file path."""
        return os.path.join(self.out_dir, "security_audit.json")

    def get_port_check_path(self, port: int) -> str:
        """Get a port check result file path."""
        return os.path.join(self.out_dir, f"port_{port}_report.json")

    def _load_prowler_findings(self) -> List[SecurityFinding]:
        """Load findings from Prowler OCSF JSON files."""
        findings: List[SecurityFinding] = []

        prowler_dir = self.get_prowler_output_dir()
        if not os.path.exists(prowler_dir):
            log.debug("security.prowler_dir_not_found", path=prowler_dir)
            return findings

        # Find all OCSF JSON files
        pattern = os.path.join(prowler_dir, "*.ocsf.json")
        files = glob.glob(pattern)

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFORMATIONAL,
        }

        status_map = {
            "FAIL": Status.FAIL,
            "PASS": Status.PASS,
            "WARNING": Status.WARNING,
        }

        framework_map = {
            "cis": Framework.CIS,
            "hipaa": Framework.HIPAA,
            "gdpr": Framework.GDPR,
            "soc2": Framework.SOC2,
            "pci": Framework.PCI,
            "nist": Framework.NIST,
            "iso27001": Framework.ISO27001,
        }

        for filepath in files:
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)

                # Handle both list and single object formats
                if not isinstance(data, list):
                    data = [data]

                for item in data:
                    # Extract fields from OCSF structure
                    severity_id = item.get("severity_id", 0)
                    severity_map_local = {
                        1: Severity.INFORMATIONAL,
                        2: Severity.LOW,
                        3: Severity.MEDIUM,
                        4: Severity.HIGH,
                        5: Severity.CRITICAL,
                        6: Severity.CRITICAL,
                    }
                    severity = severity_map_local.get(
                        severity_id, Severity.INFORMATIONAL
                    )

                    # Determine status from state_id or severity
                    state_id = item.get("state_id", 0)
                    if state_id == 2:  # Resolved
                        status = Status.PASS
                    elif state_id in (0, 1):  # Unknown or New
                        status = Status.FAIL
                    else:
                        status = Status.UNKNOWN

                    # Extract project ID
                    project_id = item.get("cloud", {}).get("project", {}).get(
                        "uid"
                    ) or item.get("cloud", {}).get("account", {}).get("uid", "unknown")

                    # Extract other fields
                    check_id = item.get("check_id", item.get("title", ""))
                    service = item.get("service", item.get("resource_type", ""))
                    resource_id = item.get("resource", {}).get(
                        "uid", item.get("resource_id", "")
                    )
                    description = item.get(
                        "description", item.get("finding_info", {}).get("title", "")
                    )
                    recommendation = item.get("remediation", {}).get("desc", "")

                    # Determine framework
                    framework_str = (
                        item.get("compliance", {}).get("framework", "unknown").lower()
                    )
                    framework = framework_map.get(framework_str, Framework.UNKNOWN)

                    finding = SecurityFinding(
                        check_id=check_id,
                        service=service,
                        status=status,
                        severity=severity,
                        framework=framework,
                        project_id=str(project_id),
                        resource_id=str(resource_id),
                        description=description,
                        recommendation=recommendation,
                        category="",
                        evidence="",
                        timestamp=item.get("time", {}).get("observed_time", ""),
                    )
                    findings.append(finding)

            except (json.JSONDecodeError, IOError) as e:
                log.warning("security.prowler_parse_error", file=filepath, error=str(e))
                continue

        return findings

    def _load_security_audit_findings(self) -> List[SecurityFinding]:
        """Load findings from local security audit."""
        audit_path = self.get_security_audit_path()
        if not os.path.exists(audit_path):
            return []

        try:
            with open(audit_path, "r") as f:
                data = json.load(f)

            findings: List[SecurityFinding] = []
            for item in data:
                finding = SecurityFinding.from_dict(item)
                findings.append(finding)
            return findings

        except (json.JSONDecodeError, IOError) as e:
            log.warning("security.audit_parse_error", file=audit_path, error=str(e))
            return []

    def _compute_security_score(self, findings: List[SecurityFinding]) -> int:
        """Calculate overall security score (0-100)."""
        if not findings:
            return 100  # No findings = perfect score

        # Base score
        score = 100

        # Deduct points based on findings
        for finding in findings:
            if finding.status == Status.FAIL:
                weight = self.SEVERITY_WEIGHTS.get(finding.severity, 5)
                score -= weight

        # Ensure score doesn't go below 0
        return max(0, min(100, score))

    def _determine_risk_level(self, score: int, critical_count: int) -> str:
        """Determine risk level based on score and critical count."""
        if critical_count > 0:
            return "CRITICAL"
        if score >= 86:
            return "MINIMAL"
        if score >= 71:
            return "LOW"
        if score >= 51:
            return "MEDIUM"
        if score >= 31:
            return "HIGH"
        return "CRITICAL"

    def _compute_compliance_scores(
        self, findings: List[SecurityFinding]
    ) -> Dict[Framework, ComplianceScore]:
        """Calculate compliance scores for each framework."""
        scores: Dict[Framework, ComplianceScore] = {}

        # Initialize all frameworks
        for fw in Framework:
            if fw != Framework.UNKNOWN:
                scores[fw] = ComplianceScore(framework=fw)

        # Count checks per framework
        for finding in findings:
            if finding.framework in scores:
                scores[finding.framework].total_checks += 1
                if finding.status == Status.PASS:
                    scores[finding.framework].passed_checks += 1
                elif finding.status == Status.FAIL:
                    scores[finding.framework].failed_checks += 1

        # Calculate percentages
        for fw in scores:
            if scores[fw].total_checks > 0:
                scores[fw].compliance_percentage = (
                    scores[fw].passed_checks / scores[fw].total_checks * 100
                )

        return scores

    def load_security_data(self, force_refresh: bool = False) -> SecurityData:
        """Load all security data from available sources."""
        cache_key = "security_data"

        # Check cache
        if not force_refresh and cache_key in self._cache:
            cached = self._cache[cache_key]
            if cached.is_valid():
                return cached

        # Load findings from all sources
        findings: List[SecurityFinding] = []
        findings.extend(self._load_prowler_findings())
        findings.extend(self._load_security_audit_findings())

        # Compute statistics
        critical_count = sum(
            1
            for f in findings
            if f.severity == Severity.CRITICAL and f.status == Status.FAIL
        )
        high_count = sum(
            1
            for f in findings
            if f.severity == Severity.HIGH and f.status == Status.FAIL
        )
        medium_count = sum(
            1
            for f in findings
            if f.severity == Severity.MEDIUM and f.status == Status.FAIL
        )
        low_count = sum(
            1
            for f in findings
            if f.severity == Severity.LOW and f.status == Status.FAIL
        )
        info_count = sum(1 for f in findings if f.severity == Severity.INFORMATIONAL)
        pass_count = sum(1 for f in findings if f.status == Status.PASS)
        fail_count = sum(1 for f in findings if f.status == Status.FAIL)

        # Collect unique projects and services
        projects = {f.project_id for f in findings if f.project_id}
        services = {f.service for f in findings if f.service}

        # Calculate scores
        security_score = self._compute_security_score(findings)
        risk_level = self._determine_risk_level(security_score, critical_count)
        compliance_scores = self._compute_compliance_scores(findings)

        # Create security data
        security_data = SecurityData(
            findings=findings,
            compliance_scores=compliance_scores,
            security_score=security_score,
            risk_level=risk_level,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            pass_count=pass_count,
            fail_count=fail_count,
            projects=projects,
            services=services,
            last_updated=time.time(),
            loaded_at=time.time(),
        )

        # Cache
        self._cache[cache_key] = security_data
        self._notify()

        return security_data

    def get_filtered_findings(
        self, filters: Optional[FindingFilters] = None
    ) -> List[SecurityFinding]:
        """Get findings matching the current or provided filters."""
        if filters is None:
            filters = self._current_filters

        data = self.load_security_data()
        return [f for f in data.findings if filters.matches(f)]

    def set_filters(self, filters: FindingFilters) -> None:
        """Set active filters and notify listeners."""
        self._current_filters = filters
        self._notify()

    def clear_filters(self) -> None:
        """Clear all active filters."""
        self._current_filters = FindingFilters()
        self._notify()

    def get_findings_by_severity(self, severity: Severity) -> List[SecurityFinding]:
        """Get all findings of a specific severity."""
        return [f for f in self.load_security_data().findings if f.severity == severity]

    def get_findings_by_framework(self, framework: Framework) -> List[SecurityFinding]:
        """Get all findings for a specific framework."""
        return [
            f for f in self.load_security_data().findings if f.framework == framework
        ]

    def get_findings_by_service(self, service: str) -> List[SecurityFinding]:
        """Get all findings for a specific service."""
        return [f for f in self.load_security_data().findings if f.service == service]

    def get_failing_findings(self) -> List[SecurityFinding]:
        """Get all failing findings."""
        return [
            f for f in self.load_security_data().findings if f.status == Status.FAIL
        ]

    def get_auto_fixable_findings(self) -> List[SecurityFinding]:
        """Get findings that have automatic remediation available."""
        fixable_check_ids = {
            "cis_gke_v1_6_0_4_2_4",  # GKE insecure kubelet port
        }
        return [
            f
            for f in self.load_security_data().findings
            if f.check_id in fixable_check_ids and f.status == Status.FAIL
        ]

    def clear_cache(self) -> None:
        """Clear all cached data."""
        self._cache.clear()
        self._notify()

    def invalidate_cache(self) -> None:
        """Invalidate security data cache."""
        cache_key = "security_data"
        if cache_key in self._cache:
            del self._cache[cache_key]
            self._notify()

    def get_stats_summary(self) -> Dict[str, Any]:
        """Get a summary of security statistics."""
        data = self.load_security_data()
        return {
            "security_score": data.security_score,
            "risk_level": data.risk_level,
            "total_findings": len(data.findings),
            "failing_findings": data.fail_count,
            "passing_findings": data.pass_count,
            "by_severity": {
                "critical": data.critical_count,
                "high": data.high_count,
                "medium": data.medium_count,
                "low": data.low_count,
                "informational": data.info_count,
            },
            "by_framework": {
                fw.value: {
                    "score": score.compliance_percentage,
                    "passed": score.passed_checks,
                    "failed": score.failed_checks,
                }
                for fw, score in data.compliance_scores.items()
            },
            "projects": list(data.projects),
            "services": list(data.services),
            "last_updated": data.last_updated,
        }

    def export_findings_json(
        self, filepath: str, filters: Optional[FindingFilters] = None
    ) -> None:
        """Export findings to JSON file."""
        import json
        from datetime import datetime, timezone

        findings = self.get_filtered_findings(filters)
        data = self.load_security_data()

        export_data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "security_score": data.security_score,
            "risk_level": data.risk_level,
            "total_findings": len(findings),
            "filters_applied": filters.to_dict() if filters else {},
            "findings": [f.to_dict() for f in findings],
        }

        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2)

        log.info("security.exported_json", filepath=filepath, count=len(findings))

    def export_findings_csv(
        self, filepath: str, filters: Optional[FindingFilters] = None
    ) -> None:
        """Export findings to CSV file."""
        import csv
        from datetime import datetime, timezone

        findings = self.get_filtered_findings(filters)

        fieldnames = [
            "check_id",
            "service",
            "severity",
            "status",
            "framework",
            "project_id",
            "resource_id",
            "description",
            "recommendation",
            "category",
            "evidence",
            "timestamp",
            "file",
            "line",
            "match_snippet",
        ]

        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in findings:
                row = finding.to_dict()
                # Add optional fields
                row["file"] = finding.file or ""
                row["line"] = finding.line or ""
                row["match_snippet"] = finding.match_snippet or ""
                writer.writerow(row)

        log.info("security.exported_csv", filepath=filepath, count=len(findings))

    def export_findings_markdown(
        self, filepath: str, filters: Optional[FindingFilters] = None
    ) -> None:
        """Export findings to Markdown report."""
        from datetime import datetime, timezone

        findings = self.get_filtered_findings(filters)
        data = self.load_security_data()

        # Group findings by severity
        by_severity: Dict[Severity, List[SecurityFinding]] = {}
        for finding in findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)

        # Build markdown content
        md_content = f"""# Security Findings Report

**Generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

## Security Score

- **Score:** {data.security_score}/100
- **Risk Level:** {data.risk_level}

## Summary

| Metric | Count |
|--------|-------|
| Total Findings | {len(findings)} |
| Failing | {data.fail_count} |
| Passing | {data.pass_count} |
| Critical | {data.critical_count} |
| High | {data.high_count} |
| Medium | {data.medium_count} |
| Low | {data.low_count} |

## Findings by Severity

"""

        # Add findings by severity
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFORMATIONAL,
        ]
        for sev in severity_order:
            if sev in by_severity:
                findings_list = by_severity[sev]
                md_content += f"\n### {sev.value.upper()} ({len(findings_list)})\n\n"
                md_content += "| Check ID | Service | Description |\n"
                md_content += "|----------|---------|-------------|\n"
                for f in findings_list:
                    desc = (
                        f.description[:80] + "..."
                        if len(f.description) > 80
                        else f.description
                    )
                    md_content += f"| {f.check_id} | {f.service} | {desc} |\n"

        # Add compliance section
        md_content += "\n## Compliance Status\n\n"
        md_content += "| Framework | Score | Passed | Failed |\n"
        md_content += "|-----------|-------|--------|--------|\n"
        for fw, score in sorted(data.compliance_scores.items()):
            md_content += f"| {fw.value.upper()} | {score.compliance_percentage:.1f}% | {score.passed_checks} | {score.failed_checks} |\n"

        with open(filepath, "w") as f:
            f.write(md_content)

        log.info("security.exported_markdown", filepath=filepath, count=len(findings))

    def export_compliance_report(
        self, filepath: str, framework: Optional[Framework] = None
    ) -> None:
        """Export compliance report for specific framework or all frameworks."""
        from datetime import datetime, timezone

        data = self.load_security_data()

        if framework:
            # Single framework report
            if framework not in data.compliance_scores:
                raise ValueError(f"No compliance data for framework: {framework}")

            score = data.compliance_scores[framework]
            framework_findings = [f for f in data.findings if f.framework == framework]

            md_content = f"""# {framework.value.upper()} Compliance Report

**Generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

## Compliance Score

- **Score:** {score.compliance_percentage:.1f}%
- **Passed Checks:** {score.passed_checks}
- **Failed Checks:** {score.failed_checks}
- **Total Checks:** {score.total_checks}

## Status: {"✅ COMPLIANT" if score.compliance_percentage >= 90 else "⚠️ NEEDS IMPROVEMENT"}

## Failed Checks

"""
            failed_checks = [f for f in framework_findings if f.status == Status.FAIL]
            for f in failed_checks:
                md_content += f"""### {f.check_id}

- **Service:** {f.service}
- **Description:** {f.description}
- **Recommendation:** {f.recommendation}
- **Resource:** {f.resource_id}

---

"""

            with open(filepath, "w") as f:
                f.write(md_content)
        else:
            # Full compliance report
            md_content = f"""# Full Compliance Report

**Generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

## Framework Summary

| Framework | Score | Passed | Failed | Status |
|-----------|-------|--------|--------|--------|
"""
            for fw, score in sorted(data.compliance_scores.items()):
                status = "✅" if score.compliance_percentage >= 90 else "⚠️"
                md_content += f"| {fw.value.upper()} | {score.compliance_percentage:.1f}% | {score.passed_checks} | {score.failed_checks} | {status} |\n"

            md_content += "\n## Detailed Framework Reports\n\n"

            for fw, score in sorted(data.compliance_scores.items()):
                fw_findings = [f for f in data.findings if f.framework == fw]
                failed = [f for f in fw_findings if f.status == Status.FAIL]

                md_content += (
                    f"### {fw.value.upper()} - {score.compliance_percentage:.1f}%\n\n"
                )
                md_content += f"**Passed:** {score.passed_checks} | **Failed:** {score.failed_checks}\n\n"

                if failed:
                    md_content += "#### Failed Checks\n\n"
                    for f in failed:
                        md_content += f"- **{f.check_id}**: {f.description[:100]}...\n"
                    md_content += "\n"

            with open(filepath, "w") as f:
                f.write(md_content)

        log.info(
            "security.exported_compliance_report",
            filepath=filepath,
            framework=framework,
        )
