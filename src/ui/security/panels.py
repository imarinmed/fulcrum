"""
Security Dashboard Overview Panel.

Provides the main security dashboard view with:
- Security score gauge
- Severity distribution
- Key metrics
- Service distribution
- Recent findings summary
"""

from typing import Optional, Dict, Any
from textual.app import ComposeResult
from textual.widgets import Static, Label, Button
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.reactive import reactive
from enum import Enum

from .store import SecurityData, SecurityFinding, Severity, Framework, SecurityStore
from .components import (
    SecurityScoreGauge,
    SeverityDistribution,
    ServiceDistribution,
    MetricsPanel,
)


class SecurityView(Enum):
    """Sub-views of the security dashboard."""

    OVERVIEW = "overview"
    FINDINGS = "findings"
    COMPLIANCE = "compliance"
    REMEDIATION = "remediation"
    TRENDS = "trends"


class OverviewPanel(Container):
    """Main overview panel showing security posture at a glance."""

    DEFAULT_CSS = """
    OverviewPanel {
        layout: vertical;
        height: 100%;
        width: 100%;
        padding: 1;
    }
    OverviewPanel .title {
        font-size: 20;
        font-weight: bold;
        margin-bottom: 1;
        content-align: center middle;
    }
    OverviewPanel .top-row {
        layout: horizontal;
        height: auto;
        margin-bottom: 1;
    }
    OverviewPanel .metrics-section {
        layout: vertical;
        width: 35;
        border: solid $primary;
        padding: 1;
    }
    OverviewPanel .distribution-section {
        layout: vertical;
        width: 30;
        border: solid $primary;
        padding: 1;
    }
    OverviewPanel .services-section {
        layout: vertical;
        width: 35;
        border: solid $primary;
        padding: 1;
    }
    OverviewPanel .findings-section {
        border: solid $primary;
        padding: 1;
        height: 30;
    }
    OverviewPanel .section-title {
        font-weight: bold;
        margin-bottom: 1;
        color: $accent;
    }
    """

    def __init__(self, store: SecurityStore, on_view_change=None):
        super().__init__()
        self._store = store
        self._on_view_change = on_view_change
        self._data: Optional[SecurityData] = None

    def compose(self) -> ComposeResult:
        yield Label("[b]🔒 Security Overview[/]", classes="title")

        with Horizontal(classes="top-row"):
            with Container(classes="metrics-section"):
                yield Label("[b]Security Score[/]", classes="section-title")
                yield SecurityScoreGauge(id="security-gauge")
                yield MetricsPanel(id="metrics-panel")

            with Container(classes="distribution-section"):
                yield Label("[b]Severity Distribution[/]", classes="section-title")
                yield SeverityDistribution(id="severity-dist")

            with Container(classes="services-section"):
                yield Label("[b]Service Distribution[/]", classes="section-title")
                yield ServiceDistribution(id="service-dist")

        with Container(classes="findings-section"):
            yield Label(
                "[b]🔴 Critical Findings Requiring Attention[/]",
                classes="section-title",
            )
            yield Label("", id="critical-findings-list")

    def on_mount(self) -> None:
        """Load data on mount."""
        self._refresh_data()

    def _refresh_data(self) -> None:
        """Refresh all data from store."""
        self._data = self._store.load_security_data()

        if not self._data:
            return

        # Update security gauge
        gauge = self.query_one("#security-gauge", SecurityScoreGauge)
        gauge.set_score(self._data.security_score, self._data.risk_level)

        # Update metrics panel
        metrics = self.query_one("#metrics-panel", MetricsPanel)
        metrics.set_metrics(
            self._data.security_score,
            self._data.critical_count,
            self._data.high_count,
            self._data.fail_count,
        )

        # Update severity distribution
        severity = self.query_one("#severity-dist", SeverityDistribution)
        severity.set_counts(
            self._data.critical_count,
            self._data.high_count,
            self._data.medium_count,
            self._data.low_count,
            self._data.info_count,
        )

        # Update service distribution
        services = self.query_one("#service-dist", ServiceDistribution)
        service_counts = {s: 0 for s in self._data.services}
        for f in self._data.findings:
            if f.service and f.status.value == "FAIL":
                service_counts[f.service] = service_counts.get(f.service, 0) + 1
        services.set_services(service_counts)

        # Update critical findings list
        critical_findings = [
            f
            for f in self._data.findings
            if f.severity == Severity.CRITICAL and f.status.value == "FAIL"
        ][:5]

        findings_label = self.query_one("#critical-findings-list", Label)
        if critical_findings:
            content = ""
            for i, finding in enumerate(critical_findings):
                content += (
                    f"[red]•[/] [{finding.service}] {finding.description[:80]}...\n"
                )
            findings_label.update(content)
        else:
            findings_label.update("[green]✅ No critical findings - great job!")

    def refresh(self) -> None:
        """Refresh the panel."""
        self._refresh_data()
        super().refresh()


class CompliancePanel(Container):
    """Panel showing compliance status for various frameworks."""

    DEFAULT_CSS = """
    CompliancePanel {
        layout: vertical;
        height: 100%;
        width: 100%;
        padding: 1;
    }
    CompliancePanel .title {
        font-size: 20;
        font-weight: bold;
        margin-bottom: 1;
        content-align: center middle;
    }
    CompliancePanel .frameworks-grid {
        layout: grid;
        grid-size: 3;
        grid-rows: 2;
        gap: 1;
        height: auto;
    }
    CompliancePanel .framework-card {
        border: solid $primary;
        padding: 1;
        height: auto;
    }
    CompliancePanel .framework-card.active {
        border: solid $accent;
        background: $surface-highlight;
    }
    CompliancePanel .framework-card:hover {
        border: solid $accent;
    }
    """

    def __init__(self, store: SecurityStore, on_framework_select=None):
        super().__init__()
        self._store = store
        self._on_framework_select = on_framework_select
        self._selected_framework = None

    def compose(self) -> ComposeResult:
        yield Label("[b]✅ Compliance Dashboard[/]", classes="title")

        yield Label("[b]Framework Compliance Status[/]", classes="section-title")
        yield Static("", id="frameworks-container")

        yield Label("", id="framework-details", classes="details")

    def on_mount(self) -> None:
        """Load compliance data on mount."""
        self._refresh_data()

    def _refresh_data(self) -> None:
        """Refresh compliance data."""
        data = self._store.load_security_data()

        if not data:
            return

        # Build framework cards
        cards = []
        for framework, score in data.compliance_scores.items():
            color = (
                "green"
                if score.compliance_percentage >= 90
                else "yellow"
                if score.compliance_percentage >= 70
                else "red"
            )
            status = (
                "✓"
                if score.compliance_percentage >= 90
                else "✗"
                if score.compliance_percentage < 50
                else "~"
            )

            card = f"""
[bold]{framework.value.upper()}[/]
[{color}]{status} {score.compliance_percentage:.1f}%[/]
Passed: {score.passed_checks}
Failed: {score.failed_checks}
            """
            cards.append(card)

        # Display frameworks
        container = self.query_one("#frameworks-container", Static)
        content = "[b]Framework Compliance Scores[/]\n\n"
        for framework, score in data.compliance_scores.items():
            color = (
                "green"
                if score.compliance_percentage >= 90
                else "yellow"
                if score.compliance_percentage >= 70
                else "red"
            )
            bar = "█" * int(score.compliance_percentage / 10)
            empty = "░" * (10 - int(score.compliance_percentage / 10))

            content += f"\n[dim]{framework.value.upper()}:[/]\n"
            content += f"[{color}]{bar}{empty}[/] {score.compliance_percentage:.1f}%\n"
            content += (
                f"   Passed: {score.passed_checks} | Failed: {score.failed_checks}\n"
            )

        container.update(content)

    def refresh(self) -> None:
        """Refresh the panel."""
        self._refresh_data()
        super().refresh()


class RemediationPanel(Container):
    """Panel showing remediation actions and fixes."""

    DEFAULT_CSS = """
    RemediationPanel {
        layout: vertical;
        height: 100%;
        width: 100%;
        padding: 1;
    }
    RemediationPanel .title {
        font-size: 20;
        font-weight: bold;
        margin-bottom: 1;
        content-align: center middle;
    }
    RemediationPanel .remediation-list {
        height: 70;
    }
    RemediationPanel .remediation-item {
        border: solid $primary;
        padding: 1;
        margin-bottom: 1;
    }
    RemediationPanel .remediation-item.auto-fixable {
        border: solid $success;
    }
    RemediationPanel .remediation-item.manual {
        border: solid $warning;
    }
    RemediationPanel .action-buttons {
        layout: horizontal;
        height: auto;
        margin-top: 1;
    }
    """

    def __init__(self, store: SecurityStore, on_fixExecute=None):
        super().__init__()
        self._store = store
        self._on_fixExecute = on_fixExecute

    def compose(self) -> ComposeResult:
        yield Label("[b]🛠️ Remediation Actions[/]", classes="title")
        yield Static("", id="remediation-content")
        yield Static("", id="manual-steps")

    def on_mount(self) -> None:
        """Load remediation data on mount."""
        self._refresh_data()

    def _refresh_data(self) -> None:
        """Refresh remediation data."""
        data = self._store.load_security_data()

        if not data:
            return

        # Auto-fixable findings
        auto_fixable = self._store.get_auto_fixable_findings()

        # Manual remediation needed
        manual_findings = [
            f
            for f in data.findings
            if f.status.value == "FAIL"
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
            if f.check_id not in {"cis_gke_v1_6_0_4_2_4"}
        ]

        # Build content
        content = "[b]Auto-Fixable Issues[/]\n\n"
        if auto_fixable:
            for finding in auto_fixable:
                content += f"[green]✓[/] [b]{finding.check_id}[/]\n"
                content += f"   {finding.description[:60]}...\n"
                content += f"   [dim]Click to apply fix[/]\n\n"
        else:
            content += "[dim]No auto-fixable issues found[/]\n"

        container = self.query_one("#remediation-content", Static)
        container.update(content)

        # Manual steps
        manual_content = "\n[b]Manual Remediation Required[/]\n\n"
        if manual_findings:
            for finding in manual_findings[:5]:
                manual_content += (
                    f"[yellow]•[/] [b]{finding.check_id}[/] - {finding.service}\n"
                )
                manual_content += f"   {finding.recommendation[:80]}...\n\n"
        else:
            manual_content += "[green]All critical/high issues can be auto-fixed![/]"

        manual_container = self.query_one("#manual-steps", Static)
        manual_container.update(manual_content)

    def refresh(self) -> None:
        """Refresh the panel."""
        self._refresh_data()
        super().refresh()


class TrendsPanel(Container):
    """Panel showing security trends over time."""

    DEFAULT_CSS = """
    TrendsPanel {
        layout: vertical;
        height: 100%;
        width: 100%;
        padding: 1;
    }
    TrendsPanel .title {
        font-size: 20;
        font-weight: bold;
        margin-bottom: 1;
        content-align: center middle;
    }
    TrendsPanel .trend-chart {
        height: 50;
        border: solid $primary;
        padding: 1;
    }
    TrendsPanel .trend-stats {
        layout: grid;
        grid-size: 4;
        grid-rows: 1;
        gap: 1;
        height: auto;
        margin-top: 1;
    }
    TrendsPanel .trend-stat {
        border: solid $primary;
        padding: 1;
        content-align: center middle;
    }
    """

    def __init__(self, store: SecurityStore):
        super().__init__()
        self._store = store

    def compose(self) -> ComposeResult:
        yield Label("[b]📈 Security Trends[/]", classes="title")
        yield Static("", id="trend-chart", classes="trend-chart")
        yield Static("", id="trend-stats", classes="trend-stats")

    def on_mount(self) -> None:
        """Load trend data on mount."""
        self._refresh_data()

    def _refresh_data(self) -> None:
        """Refresh trend data."""
        data = self._store.load_security_data()

        if not data:
            return

        # Simple trend visualization
        score = data.security_score
        if score >= 80:
            trend = "📈 Improving"
            trend_dir = "improving"
        elif score >= 60:
            trend = "➡️ Stable"
            trend_dir = "stable"
        else:
            trend = "📉 Declining"
            trend_dir = "declining"

        # Update chart
        chart = self.query_one("#trend-chart", Static)
        chart.update(
            f"""
[bold]Security Score Trend[/]

Current Score: {score}/100

{trend}

[b]Finding Volume:[/]
Total Findings: {len(data.findings)}
Failing: {data.fail_count}
Passing: {data.pass_count}

[b]Severity Breakdown:[/]
Critical: {data.critical_count}
High: {data.high_count}
Medium: {data.medium_count}
Low: {data.low_count}
            """
        )

        # Update stats
        stats = self.query_one("#trend-stats", Static)
        stats.update(
            f"""
[div class="trend-stat"]
    [b]{data.critical_count}[/]
    [dim]Critical[/dim]
[/div]
[div class="trend-stat"]
    [b]{data.high_count}[/]
    [dim]High[/dim]
[/div]
[div class="trend-stat"]
    [b]{data.medium_count}[/]
    [dim]Medium[/dim]
[/div]
[div class="trend-stat"]
    [b]{data.low_count}[/]
    [dim]Low[/dim]
[/div]
            """
        )

    def refresh(self) -> None:
        """Refresh the panel."""
        self._refresh_data()
        super().refresh()


class SecurityPanels(Container):
    """Container for all security dashboard panels with navigation."""

    DEFAULT_CSS = """
    SecurityPanels {
        layout: vertical;
        height: 100%;
        width: 100%;
    }
    SecurityPanels .nav-bar {
        layout: horizontal;
        height: auto;
        dock: top;
        background: $surface;
        border-bottom: solid $primary;
    }
    SecurityPanels .nav-button {
        margin: 0;
        padding: 0 2;
        border: none;
    }
    SecurityPanels .nav-button.active {
        background: $accent;
        color: $text;
    }
    SecurityPanels .panel-container {
        flex-grow: 1;
    }
    """

    def __init__(self, store: SecurityStore):
        super().__init__()
        self._store = store
        self._current_view: SecurityView = SecurityView.OVERVIEW

    def compose(self) -> ComposeResult:
        yield Horizontal(classes="nav-bar", id="nav-bar")
        yield Container(classes="panel-container", id="panel-container")

    def on_mount(self) -> None:
        """Initialize the dashboard."""
        self._create_nav_bar()
        self._show_panel(self._current_view)

    def _create_nav_bar(self) -> None:
        """Create the navigation bar."""
        nav_bar = self.query_one("#nav-bar", Horizontal)
        nav_bar.remove_children()

        views = [
            ("Overview", SecurityView.OVERVIEW),
            ("Findings", SecurityView.FINDINGS),
            ("Compliance", SecurityView.COMPLIANCE),
            ("Remediation", SecurityView.REMEDIATION),
            ("Trends", SecurityView.TRENDS),
        ]

        for name, view in views:
            btn = Button(name, id=f"nav-{view.value}", classes="nav-button")
            if view == self._current_view:
                btn.add_class("active")
            nav_bar.append(btn)

    def _show_panel(self, view: SecurityView) -> None:
        """Show the panel for the given view."""
        container = self.query_one("#panel-container", Container)
        container.remove_children()

        panels = {
            SecurityView.OVERVIEW: lambda: OverviewPanel(self._store),
            SecurityView.FINDINGS: lambda: self._create_findings_panel(),
            SecurityView.COMPLIANCE: lambda: CompliancePanel(self._store),
            SecurityView.REMEDIATION: lambda: RemediationPanel(self._store),
            SecurityView.TRENDS: lambda: TrendsPanel(self._store),
        }

        if view in panels:
            container.mount(panels[view]())

    def _create_findings_panel(self):
        """Create the findings panel with the store."""
        from .findings import FindingsPanel

        return FindingsPanel(self._store)

    def on_button_pressed(self, event) -> None:
        """Handle navigation button presses."""
        button_id = event.button.id
        if button_id and button_id.startswith("nav-"):
            view_name = button_id.replace("nav-", "")
            try:
                view = SecurityView(view_name)
                self._current_view = view
                self._create_nav_bar()
                self._show_panel(view)
            except ValueError:
                pass

    def switch_view(self, view: SecurityView) -> None:
        """Switch to a different view programmatically."""
        self._current_view = view
        self._create_nav_bar()
        self._show_panel(view)

    def refresh_current_panel(self) -> None:
        """Refresh the current panel's data."""
        container = self.query_one("#panel-container", Container)
        for child in container.children:
            if hasattr(child, "refresh"):
                child.refresh()
