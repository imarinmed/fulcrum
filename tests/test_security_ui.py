"""
Tests for Security TUI Components.

Tests cover:
- SecurityStore data loading and aggregation
- Security score calculations
- Compliance score computations
- Finding filters and matching
- Export functionality (JSON, CSV, Markdown)
"""

import json
import tempfile
import os
from pathlib import Path
from datetime import datetime, timezone
import pytest

from ui.security.store import (
    SecurityStore,
    SecurityData,
    SecurityFinding,
    Severity,
    Status,
    Framework,
    FindingFilters,
    ComplianceScore,
)


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        SecurityFinding(
            check_id="cis_gke_v1_6_0_4_2_4",
            service="container",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            framework=Framework.CIS,
            project_id="test-project-1",
            resource_id="cluster-1",
            description="GKE cluster has insecure kubelet read-only port exposed",
            recommendation="Disable insecure-kubelet-readonly-port flag",
            category="Kubernetes Security",
            evidence="Port 10255 is open",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        SecurityFinding(
            check_id="gcp_iam_privilege_escalation",
            service="iam",
            status=Status.FAIL,
            severity=Severity.HIGH,
            framework=Framework.CIS,
            project_id="test-project-1",
            resource_id="service-account-1",
            description="Service account has overly permissive roles",
            recommendation="Remove unnecessary IAM roles",
            category="IAM Security",
            evidence="roles/owner granted",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        SecurityFinding(
            check_id="gcp_storage_bucket_public",
            service="storage",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            framework=Framework.GDPR,
            project_id="test-project-2",
            resource_id="bucket-1",
            description="Storage bucket is publicly accessible",
            recommendation="Make bucket private or use IAM controls",
            category="Storage Security",
            evidence="allUsers granted storage.objectViewer",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
        SecurityFinding(
            check_id="gcp_compute_no_ip_forwarding",
            service="compute",
            status=Status.PASS,
            severity=Severity.INFORMATIONAL,
            framework=Framework.CIS,
            project_id="test-project-1",
            resource_id="instance-1",
            description="Instance does not have IP forwarding enabled",
            recommendation="No action needed",
            category="Compute Security",
            evidence="IP forwarding is disabled",
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    ]


@pytest.fixture
def temp_out_dir(tmp_path):
    """Create temporary output directory with mock data."""
    prowler_dir = tmp_path / "prowler_output"
    prowler_dir.mkdir()

    # Create mock OCSF JSON file
    ocsf_file = prowler_dir / "test-project-1.ocsf.json"
    ocsf_file.write_text(
        json.dumps(
            [
                {
                    "check_id": "cis_gke_v1_6_0_4_2_4",
                    "service": "container",
                    "status": "FAIL",
                    "severity_id": 5,
                    "state_id": 1,
                    "cloud": {
                        "project": {"uid": "test-project-1"},
                        "account": {"uid": "test-project-1"},
                    },
                    "resource": {"uid": "cluster-1"},
                    "description": "GKE cluster has insecure kubelet port",
                    "remediation": {"desc": "Disable the insecure port"},
                    "compliance": {"framework": "CIS"},
                    "time": {"observed_time": datetime.now(timezone.utc).isoformat()},
                },
                {
                    "check_id": "gcp_iam_privilege_escalation",
                    "service": "iam",
                    "status": "FAIL",
                    "severity_id": 4,
                    "state_id": 1,
                    "cloud": {
                        "project": {"uid": "test-project-1"},
                        "account": {"uid": "test-project-1"},
                    },
                    "resource": {"uid": "service-account-1"},
                    "description": "Service account has overly permissive roles",
                    "remediation": {"desc": "Remove unnecessary roles"},
                    "compliance": {"framework": "CIS"},
                    "time": {"observed_time": datetime.now(timezone.utc).isoformat()},
                },
            ]
        )
    )

    return str(tmp_path)


class TestSecurityFinding:
    """Tests for SecurityFinding model."""

    def test_to_dict(self, sample_findings):
        """Test converting finding to dictionary."""
        finding = sample_findings[0]
        result = finding.to_dict()

        assert result["check_id"] == "cis_gke_v1_6_0_4_2_4"
        assert result["service"] == "container"
        assert result["severity"] == "critical"
        assert result["status"] == "FAIL"
        assert result["framework"] == "cis"
        assert result["project_id"] == "test-project-1"

    def test_from_dict(self):
        """Test creating finding from dictionary."""
        data = {
            "check_id": "test_check",
            "service": "compute",
            "status": "FAIL",
            "severity": "high",
            "framework": "cis",
            "project_id": "project-1",
            "resource_id": "resource-1",
            "description": "Test description",
            "recommendation": "Fix it",
            "category": "Test",
            "evidence": "Evidence",
        }

        finding = SecurityFinding.from_dict(data)

        assert finding.check_id == "test_check"
        assert finding.service == "compute"
        assert finding.severity == Severity.HIGH
        assert finding.status == Status.FAIL


class TestFindingFilters:
    """Tests for FindingFilters."""

    def test_matches_severity(self, sample_findings):
        """Test filtering by severity."""
        filters = FindingFilters(severities={Severity.CRITICAL})

        critical = sample_findings[0]
        high = sample_findings[1]

        assert filters.matches(critical) is True
        assert filters.matches(high) is False

    def test_matches_status(self, sample_findings):
        """Test filtering by status."""
        filters = FindingFilters(statuses={Status.FAIL})

        failing = sample_findings[0]
        passing = sample_findings[3]

        assert filters.matches(failing) is True
        assert filters.matches(passing) is False

    def test_matches_framework(self, sample_findings):
        """Test filtering by framework."""
        filters = FindingFilters(frameworks={Framework.CIS})

        cis_finding = sample_findings[0]
        gdpr_finding = sample_findings[2]

        assert filters.matches(cis_finding) is True
        assert filters.matches(gdpr_finding) is False

    def test_matches_search_query(self, sample_findings):
        """Test filtering by search query."""
        filters = FindingFilters(search_query="kubelet")

        result = filters.matches(sample_findings[0])
        assert result is True

        result = filters.matches(sample_findings[1])
        assert result is False

    def test_matches_show_only_failures(self, sample_findings):
        """Test filtering to show only failures."""
        filters = FindingFilters(show_only_failures=True)

        assert filters.matches(sample_findings[0]) is True
        assert filters.matches(sample_findings[3]) is False

    def test_matches_combined_filters(self, sample_findings):
        """Test combining multiple filters."""
        filters = FindingFilters(
            severities={Severity.CRITICAL, Severity.HIGH},
            statuses={Status.FAIL},
        )

        # Should match: critical + fail
        assert filters.matches(sample_findings[0]) is True

        # Should match: high + fail
        assert filters.matches(sample_findings[1]) is True

        # Should not match: medium (not in severities)
        assert filters.matches(sample_findings[2]) is False

        # Should not match: pass (not in statuses)
        assert filters.matches(sample_findings[3]) is False

    def test_to_dict(self):
        """Test converting filters to dictionary."""
        filters = FindingFilters(
            severities={Severity.CRITICAL, Severity.HIGH},
            frameworks={Framework.CIS},
            search_query="test",
            show_only_failures=True,
        )

        result = filters.to_dict()

        assert "critical" in result["severities"]
        assert "high" in result["severities"]
        assert "cis" in result["frameworks"]
        assert result["search_query"] == "test"
        assert result["show_only_failures"] is True


class TestSecurityStore:
    """Tests for SecurityStore."""

    def test_load_security_data_from_ocsf(self, temp_out_dir):
        """Test loading security data from OCSF JSON files."""
        store = SecurityStore(temp_out_dir)
        data = store.load_security_data()

        assert data is not None
        assert len(data.findings) >= 1

    def test_security_score_calculation(self, sample_findings):
        """Test security score calculation."""
        store = SecurityStore("/nonexistent")

        # All findings fail - score should be low
        score = store._compute_security_score(sample_findings)

        # Critical: -15, High: -10, Medium: -5, Low: -1, Info: 0
        # Base 100 - (15 + 10 + 5) = 70
        assert score == 70

    def test_security_score_perfect(self):
        """Test security score with no failures."""
        store = SecurityStore("/nonexistent")

        passing_finding = SecurityFinding(
            check_id="test_pass",
            service="compute",
            status=Status.PASS,
            severity=Severity.INFORMATIONAL,
            framework=Framework.CIS,
            project_id="p1",
            resource_id="r1",
            description="Passing check",
            recommendation="",
            category="",
            evidence="",
        )

        score = store._compute_security_score([passing_finding])
        assert score == 100

    def test_determine_risk_level(self):
        """Test risk level determination."""
        store = SecurityStore("/nonexistent")

        assert store._determine_risk_level(95, 0) == "MINIMAL"
        assert store._determine_risk_level(80, 0) == "LOW"
        assert store._determine_risk_level(65, 0) == "MEDIUM"
        assert store._determine_risk_level(45, 0) == "HIGH"
        assert store._determine_risk_level(30, 0) == "CRITICAL"
        assert (
            store._determine_risk_level(50, 1) == "CRITICAL"
        )  # Any critical issues = CRITICAL

    def test_compute_compliance_scores(self, sample_findings):
        """Test compliance score computation."""
        store = SecurityStore("/nonexistent")

        scores = store._compute_compliance_scores(sample_findings)

        # Check CIS framework
        cis_score = scores[Framework.CIS]
        assert cis_score.total_checks >= 2
        assert cis_score.failed_checks >= 1
        assert cis_score.passed_checks >= 1

    def test_get_filtered_findings(self, temp_out_dir):
        """Test getting filtered findings."""
        store = SecurityStore(temp_out_dir)

        # Get all findings
        all_findings = store.get_filtered_findings()
        assert len(all_findings) >= 1

        # Filter by critical severity
        filters = FindingFilters(severities={Severity.CRITICAL})
        critical_findings = store.get_filtered_findings(filters)

        for f in critical_findings:
            assert f.severity == Severity.CRITICAL

    def test_get_failing_findings(self, temp_out_dir):
        """Test getting only failing findings."""
        store = SecurityStore(temp_out_dir)

        failing = store.get_failing_findings()

        for f in failing:
            assert f.status == Status.FAIL

    def test_get_auto_fixable_findings(self, temp_out_dir):
        """Test getting auto-fixable findings."""
        store = SecurityStore(temp_out_dir)

        auto_fixable = store.get_auto_fixable_findings()

        # Should contain GKE insecure port finding
        check_ids = [f.check_id for f in auto_fixable]
        assert "cis_gke_v1_6_0_4_2_4" in check_ids

    def test_get_stats_summary(self, temp_out_dir):
        """Test getting statistics summary."""
        store = SecurityStore(temp_out_dir)

        summary = store.get_stats_summary()

        assert "security_score" in summary
        assert "risk_level" in summary
        assert "total_findings" in summary
        assert "failing_findings" in summary
        assert "by_severity" in summary
        assert "by_framework" in summary
        assert "projects" in summary
        assert "services" in summary

    def test_cache_invalidation(self, temp_out_dir):
        """Test cache invalidation."""
        store = SecurityStore(temp_out_dir)

        # Load data
        data1 = store.load_security_data()

        # Invalidate cache
        store.invalidate_cache()

        # Load again (should work)
        data2 = store.load_security_data()

        assert data2 is not None


class TestSecurityStoreExport:
    """Tests for SecurityStore export functionality."""

    def test_export_findings_json(self, temp_out_dir):
        """Test exporting findings to JSON."""
        store = SecurityStore(temp_out_dir)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name

        try:
            store.export_findings_json(filepath)

            with open(filepath, "r") as f:
                data = json.load(f)

            assert "export_timestamp" in data
            assert "security_score" in data
            assert "findings" in data
            assert isinstance(data["findings"], list)
        finally:
            os.unlink(filepath)

    def test_export_findings_csv(self, temp_out_dir):
        """Test exporting findings to CSV."""
        store = SecurityStore(temp_out_dir)

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            filepath = f.name

        try:
            store.export_findings_csv(filepath)

            with open(filepath, "r") as f:
                lines = f.readlines()

            # Should have header and at least one data row
            assert len(lines) >= 2
            assert "check_id" in lines[0].lower()
        finally:
            os.unlink(filepath)

    def test_export_findings_markdown(self, temp_out_dir):
        """Test exporting findings to Markdown."""
        store = SecurityStore(temp_out_dir)

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            filepath = f.name

        try:
            store.export_findings_markdown(filepath)

            with open(filepath, "r") as f:
                content = f.read()

            assert "# Security Findings Report" in content
            assert "## Summary" in content
            assert "## Findings by Severity" in content
        finally:
            os.unlink(filepath)

    def test_export_compliance_report(self, temp_out_dir):
        """Test exporting compliance report."""
        store = SecurityStore(temp_out_dir)

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            filepath = f.name

        try:
            # Export full compliance report
            store.export_compliance_report(filepath)

            with open(filepath, "r") as f:
                content = f.read()

            assert "# Full Compliance Report" in content
            assert "## Framework Summary" in content
        finally:
            os.unlink(filepath)

    def test_export_compliance_report_specific_framework(self, temp_out_dir):
        """Test exporting compliance report for specific framework."""
        store = SecurityStore(temp_out_dir)

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            filepath = f.name

        try:
            # Export CIS compliance report
            store.export_compliance_report(filepath, Framework.CIS)

            with open(filepath, "r") as f:
                content = f.read()

            assert "# CIS Compliance Report" in content
            assert "## Compliance Score" in content
            assert "## Failed Checks" in content
        finally:
            os.unlink(filepath)

    def test_export_with_filters(self, temp_out_dir):
        """Test exporting with filters applied."""
        store = SecurityStore(temp_out_dir)

        filters = FindingFilters(
            severities={Severity.CRITICAL},
            show_only_failures=True,
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name

        try:
            store.export_findings_json(filepath, filters)

            with open(filepath, "r") as f:
                data = json.load(f)

            assert data["filters_applied"]["severities"] == ["critical"]
            assert data["filters_applied"]["show_only_failures"] is True

            # All exported findings should be critical and failing
            for finding in data["findings"]:
                assert finding["severity"] == "critical"
                assert finding["status"] == "FAIL"
        finally:
            os.unlink(filepath)


class TestSecurityData:
    """Tests for SecurityData model."""

    def test_is_valid_within_ttl(self):
        """Test data validity within TTL."""
        data = SecurityData(
            findings=[],
            loaded_at=0.0,  # Will be updated
        )
        data.loaded_at = data.loaded_at or data.last_updated

        # Data should be valid if loaded recently
        data.loaded_at = 0.0
        data.last_updated = 0.0

        import time

        data.loaded_at = time.time()

        assert data.is_valid() is True

    def test_is_valid_expired(self):
        """Test data validity when TTL expired."""
        import time

        data = SecurityData(
            findings=[],
            loaded_at=0.0,
            valid_for_seconds=1,  # 1 second TTL
        )
        data.loaded_at = time.time() - 10  # 10 seconds ago

        assert data.is_valid() is False


class TestComplianceScore:
    """Tests for ComplianceScore model."""

    def test_pass_rate(self):
        """Test pass rate calculation."""
        score = ComplianceScore(
            framework=Framework.CIS,
            total_checks=10,
            passed_checks=8,
            failed_checks=2,
        )

        assert score.pass_rate == 80.0

    def test_pass_rate_no_checks(self):
        """Test pass rate with no checks."""
        score = ComplianceScore(
            framework=Framework.CIS,
            total_checks=0,
            passed_checks=0,
            failed_checks=0,
        )

        assert score.pass_rate == 0.0
