"""
Security Visualization Components.

Provides:
- Security score gauge (animated radial gauge)
- Severity distribution sparkline
- Compliance framework cards
- Status indicators and badges
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum
from textual.app import ComposeResult
from textual.widgets import Static, ProgressBar, Label
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual import events

from .store import Severity, Status, Framework, SecurityData


class SecurityScoreGauge(Static):
    """Animated radial gauge showing security score (0-100)."""

    DEFAULT_CSS = """
    SecurityScoreGauge {
        layout: vertical;
        height: auto;
        width: auto;
        align: center top;
    }
    SecurityScoreGauge .gauge-container {
        width: 120px;
        height: 120px;
        border: solid $primary;
        border-radius: 50%;
        align: center center;
        position: relative;
    }
    SecurityScoreGauge .score-label {
        content-align: center middle;
        font-size: 28px;
        font-weight: bold;
    }
    SecurityScoreGauge .risk-label {
        content-align: center middle;
        font-size: 14px;
        margin-top: 4;
    }
    SecurityScoreGauge .progress-ring {
        width: 100%;
        height: 100%;
    }
    """

    score: reactive[int] = reactive(0)
    risk_level: reactive[str] = reactive("UNKNOWN")
    animated: reactive[bool] = reactive(True)

    def __init__(self, score: int = 0, risk_level: str = "UNKNOWN"):
        super().__init__()
        self._target_score = score
        self._target_risk = risk_level

    def watch_score(self, score: int) -> None:
        """Update display when score changes."""
        self._target_score = score
        self._update_display()

    def watch_risk_level(self, level: str) -> None:
        """Update risk label when level changes."""
        self._target_risk = level
        self._update_display()

    def _get_color_for_score(self, score: int) -> str:
        """Get color based on score value."""
        if score >= 80:
            return "green"
        elif score >= 60:
            return "yellow"
        elif score >= 40:
            return "orange"
        else:
            return "red"

    def _get_risk_label(self) -> str:
        """Get human-readable risk label."""
        if self._target_risk == "CRITICAL":
            return "🔴 CRITICAL RISK"
        elif self._target_risk == "HIGH":
            return "🟠 HIGH RISK"
        elif self._target_risk == "MEDIUM":
            return "🟡 MEDIUM RISK"
        elif self._target_risk == "LOW":
            return "🟢 LOW RISK"
        elif self._target_risk == "MINIMAL":
            return "✅ MINIMAL RISK"
        return "⚪ UNKNOWN RISK"

    def _get_arc_segments(self, score: int) -> str:
        """Generate SVG arc segments for the gauge."""
        import math

        # Calculate arc
        percentage = score / 100.0
        angle = 2 * math.pi * percentage
        radius = 40
        center_x = 50
        center_y = 50

        # Start from top (-90 degrees)
        x1 = center_x + radius * math.cos(-math.pi / 2)
        y1 = center_y + radius * math.sin(-math.pi / 2)
        x2 = center_x + radius * math.cos(angle - math.pi / 2)
        y2 = center_y + radius * math.sin(angle - math.pi / 2)

        # Large arc flag
        large_arc = 1 if percentage > 0.5 else 0

        color = self._get_color_for_score(score)

        # Background arc (gray)
        bg_arc = f"M 10,50 A 40,40 0 1,1 90,50 A 40,40 0 1,1 10,50"

        # Foreground arc (colored)
        if percentage > 0:
            fg_arc = f"M 50,10 A 40,40 0 {large_arc},1 {x2:.1f},{y2:.1f}"
        else:
            fg_arc = ""

        return f"""
        <svg viewBox="0 0 100 100" class="gauge-svg">
            <path d="{bg_arc}" fill="none" stroke="#333" stroke-width="8"/>
            <path d="{fg_arc}" fill="none" stroke="{color}" stroke-width="8" stroke-linecap="round"/>
            <text x="50" y="55" text-anchor="middle" font-size="24" font-weight="bold" fill="{color}">{score}</text>
            <text x="50" y="70" text-anchor="middle" font-size="8" fill="#888">/ 100</text>
        </svg>
        """

    def _update_display(self) -> None:
        """Update the gauge display."""
        color = self._get_color_for_score(self._target_score)
        risk_text = self._get_risk_label()

        self.update(
            f"""
[bold]{self._target_score}[/] / 100

[{color}]{risk_text}[/]
            """
        )

    def on_mount(self) -> None:
        """Initialize display on mount."""
        self.score = self._target_score
        self.risk_level = self._target_risk

    def set_score(self, score: int, risk_level: str) -> None:
        """Set the security score and risk level."""
        self._target_score = score
        self._target_risk = risk_level
        self.refresh()

    def compose(self) -> ComposeResult:
        yield Static("", id="gauge-content")


class SeverityDistribution(Static):
    """Horizontal bar chart showing severity distribution."""

    DEFAULT_CSS = """
    SeverityDistribution {
        layout: vertical;
        height: auto;
        width: auto;
    }
    SeverityDistribution .bar-row {
        layout: horizontal;
        height: auto;
        margin-bottom: 1;
    }
    SeverityDistribution .bar-label {
        width: 60;
        content-align: right center;
    }
    SeverityDistribution .bar-container {
        width: 120;
        height: 16;
        border: solid #444;
        margin-left: 8;
    }
    SeverityDistribution .bar-fill {
        height: 100%;
    }
    SeverityDistribution .bar-count {
        width: 40;
        margin-left: 8;
        content-align: left center;
    }
    """

    critical: reactive[int] = reactive(0)
    high: reactive[int] = reactive(0)
    medium: reactive[int] = reactive(0)
    low: reactive[int] = reactive(0)
    info: reactive[int] = reactive(0)

    def watch_critical(self, value: int) -> None:
        self._update_display()

    def watch_high(self, value: int) -> None:
        self._update_display()

    def watch_medium(self, value: int) -> None:
        self._update_display()

    def watch_low(self, value: int) -> None:
        self._update_display()

    def watch_info(self, value: int) -> None:
        self._update_display()

    def _get_bar(self, label: str, count: int, color: str, max_count: int) -> str:
        """Generate a single bar row."""
        if max_count > 0:
            width = int((count / max_count) * 100)
        else:
            width = 0

        bar = "█" * width
        return f"{label:<10} │{bar}│ {count}"

    def _update_display(self) -> None:
        """Update the distribution display."""
        max_count = max(self.critical, self.high, self.medium, self.low, self.info, 1)

        content = "[bold]Severity Distribution[/]\n\n"
        content += self._get_bar("🔴 Critical", self.critical, "red", max_count) + "\n"
        content += self._get_bar("🟠 High", self.high, "orange", max_count) + "\n"
        content += self._get_bar("🟡 Medium", self.medium, "yellow", max_count) + "\n"
        content += self._get_bar("🟢 Low", self.low, "green", max_count) + "\n"
        content += self._get_bar("⚪ Info", self.info, "white", max_count)

        self.update(content)

    def set_counts(
        self, critical: int, high: int, medium: int, low: int, info: int
    ) -> None:
        """Set all severity counts."""
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
        self.info = info
        self.refresh()

    def compose(self) -> ComposeResult:
        yield Static("", id="severity-content")


class ComplianceCard(Static):
    """Card showing compliance status for a single framework."""

    DEFAULT_CSS = """
    ComplianceCard {
        border: solid $primary;
        padding: 1;
        width: 100%;
        height: auto;
    }
    ComplianceCard.active {
        border: solid $accent;
        background: $surface-highlight;
    }
    ComplianceCard .framework-name {
        font-weight: bold;
        font-size: 16;
    }
    ComplianceCard .compliance-score {
        font-size: 24;
        font-weight: bold;
    }
    ComplianceCard .check-count {
        font-size: 12;
        color: $text-muted;
    }
    """

    framework: reactive[str] = reactive("")
    score: reactive[float] = reactive(0.0)
    passed: reactive[int] = reactive(0)
    failed: reactive[int] = reactive(0)
    active: reactive[bool] = reactive(False)

    def __init__(
        self, framework: str, score: float = 0.0, passed: int = 0, failed: int = 0
    ):
        super().__init__()
        self.framework = framework
        self.score = score
        self.passed = passed
        self.failed = failed

    def watch_score(self, score: float) -> None:
        self._update_display()

    def watch_active(self, active: bool) -> None:
        self._refresh_classes()

    def _get_color_for_score(self, score: float) -> str:
        """Get color based on compliance score."""
        if score >= 90:
            return "green"
        elif score >= 70:
            return "yellow"
        elif score >= 50:
            return "orange"
        else:
            return "red"

    def _get_framework_icon(self, framework: str) -> str:
        """Get icon for framework."""
        icons = {
            "cis": "🏛️",
            "hipaa": "🏥",
            "gdpr": "🇪🇺",
            "soc2": "📋",
            "pci": "💳",
            "nist": "🔒",
            "iso27001": "📜",
        }
        return icons.get(framework.lower(), "📋")

    def _update_display(self) -> None:
        """Update card content."""
        color = self._get_color_for_score(self.score)
        icon = self._get_framework_icon(self.framework)

        status = "✓" if self.score >= 90 else "✗" if self.score < 50 else "~"

        self.update(
            f"[b]{icon} {self.framework.upper()}[/]\n"
            f"[{color}]{status} {self.score:.1f}%[/] compliance\n"
            f"[dim]Passed: {self.passed} | Failed: {self.failed}[/]"
        )

    def _refresh_classes(self) -> None:
        """Refresh CSS classes."""
        self.remove_class("active")
        if self.active:
            self.add_class("active")

    def on_mount(self) -> None:
        """Initialize display on mount."""
        self._update_display()
        self._refresh_classes()

    def set_data(self, framework: str, score: float, passed: int, failed: int) -> None:
        """Update card data."""
        self.framework = framework
        self.score = score
        self.passed = passed
        self.failed = failed
        self.refresh()

    def set_active(self, active: bool) -> None:
        """Set the active state of this card."""
        self.active = active


class ServiceDistribution(Static):
    """Shows findings distribution across GCP services."""

    DEFAULT_CSS = """
    ServiceDistribution {
        layout: vertical;
        height: auto;
        width: auto;
    }
    """

    def __init__(self, services: Dict[str, int] = None):
        super().__init__()
        self._services = services or {}

    def watch_services(self, services: Dict[str, int]) -> None:
        self._services = services
        self._update_display()

    def _update_display(self) -> None:
        """Update the service distribution display."""
        if not self._services:
            self.update("[dim]No service data available[/]")
            return

        # Sort by count and take top 5
        sorted_services = sorted(
            self._services.items(), key=lambda x: x[1], reverse=True
        )[:5]
        max_count = sorted_services[0][1] if sorted_services else 1

        content = "[bold]Service Distribution[/]\n\n"
        for service, count in sorted_services:
            bar_len = int((count / max_count) * 20)
            bar = "█" * bar_len
            content += f"{service:<20} │{bar}│ {count}\n"

        self.update(content.rstrip())

    def set_services(self, services: Dict[str, int]) -> None:
        """Update service distribution."""
        self._services = services
        self.refresh()

    def compose(self) -> ComposeResult:
        yield Static("", id="service-content")


class FindingBadge(Static):
    """Badge showing finding status with appropriate styling."""

    DEFAULT_CSS = """
    FindingBadge {
        padding: 0 1;
        height: auto;
        border-radius: 3;
    }
    FindingBadge.critical {
        background: #ff4444;
        color: white;
    }
    FindingBadge.high {
        background: #ff8800;
        color: white;
    }
    FindingBadge.medium {
        background: #ffdd00;
        color: black;
    }
    FindingBadge.low {
        background: #00cc00;
        color: white;
    }
    FindingBadge.informational {
        background: #666666;
        color: white;
    }
    FindingBadge.pass {
        background: #00aa00;
        color: white;
    }
    FindingBadge.fail {
        background: #cc0000;
        color: white;
    }
    FindingBadge.warning {
        background: #dd8800;
        color: white;
    }
    """

    def __init__(self, text: str, severity: str = "", status: str = ""):
        super().__init__(text)
        if severity:
            self.add_class(severity.lower())
        elif status:
            self.add_class(status.lower())

    @classmethod
    def from_finding(cls, finding) -> "FindingBadge":
        """Create badge from finding object."""
        if finding.severity:
            return cls(
                finding.severity.upper(),
                severity=finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity),
            )
        return cls(
            finding.status.upper(),
            status=finding.status.value
            if hasattr(finding.status, "value")
            else str(finding.status),
        )


class MetricsPanel(Static):
    """Panel showing key security metrics at a glance."""

    DEFAULT_CSS = """
    MetricsPanel {
        layout: grid;
        grid-size: 3;
        grid-rows: 1;
        gap: 1;
        height: auto;
        width: auto;
    }
    MetricsPanel .metric {
        border: solid $primary;
        padding: 1;
        align: center top;
    }
    MetricsPanel .metric-value {
        font-size: 28;
        font-weight: bold;
    }
    MetricsPanel .metric-label {
        font-size: 12;
        color: $text-muted;
        margin-top: 1;
    }
    """

    def __init__(self):
        super().__init__()
        self._metrics = {}

    def set_metrics(
        self, security_score: int, critical_count: int, high_count: int, fail_count: int
    ) -> None:
        """Set all metrics."""
        self._metrics = {
            "score": security_score,
            "critical": critical_count,
            "high": high_count,
            "failing": fail_count,
        }
        self._update_display()

    def _update_display(self) -> None:
        """Update metrics display."""
        score_color = (
            "green"
            if self._metrics.get("score", 0) >= 80
            else "yellow"
            if self._metrics.get("score", 0) >= 60
            else "red"
        )

        self.update(
            f"""
[div class="metric"]
    [div class="metric-value"][{score_color}]{self._metrics.get("score", 0)}[/][/]
    [div class="metric-label"]Security Score[/]
[/div]
[div class="metric"]
    [div class="metric-value"][red]{self._metrics.get("critical", 0)}[/][/div]
    [div class="metric-label"]Critical Issues[/div]
[/div]
[div class="metric"]
    [div class="metric-value"][orange]{self._metrics.get("high", 0)}[/][/div]
    [div class="metric-label"]High Priority[/div]
[/div]
[div class="metric"]
    [div class="metric-value"][yellow]{self._metrics.get("failing", 0)}[/][/div]
    [div class="metric-label"]Total Failing[/div]
[/div]
            """
        )

    def compose(self) -> ComposeResult:
        yield Static("", id="metrics-content")


class TrendIndicator(Static):
    """Shows trend direction (up/down/stable) with icon."""

    DEFAULT_CSS = """
    TrendIndicator {
        height: auto;
        width: auto;
    }
    TrendIndicator.improving {
        color: green;
    }
    TrendIndicator.declining {
        color: red;
    }
    TrendIndicator.stable {
        color: yellow;
    }
    """

    def __init__(self, direction: str = "stable", value: str = ""):
        super().__init__()
        self._direction = direction
        self._value = value

    def _get_icon(self) -> str:
        """Get icon based on direction."""
        if self._direction == "improving":
            return "📈"
        elif self._direction == "declining":
            return "📉"
        else:
            return "➡️"

    def _update_display(self) -> None:
        """Update display."""
        icon = self._get_icon()
        self.update(f"{icon} {self._value}")

    def set_trend(self, direction: str, value: str = "") -> None:
        """Set trend direction and optional value."""
        self._direction = direction
        self._value = value
        self.remove_class("improving", "declining", "stable")
        self.add_class(direction)
        self.refresh()

    def compose(self) -> ComposeResult:
        yield Static("", id="trend-content")
