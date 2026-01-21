"""
Security Findings Table.

Provides a filterable, sortable table for viewing security findings with:
- Multi-column sorting
- Filtering by severity, status, framework, service
- Search functionality
- Keyboard navigation
- Detail view on selection
"""

from typing import Optional, List, Dict, Any, Callable
from textual.app import ComposeResult
from textual.widgets import DataTable, Static, Input, Button, Label
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive

from .store import (
    SecurityFinding,
    Severity,
    Status,
    Framework,
    FindingFilters,
    SecurityStore,
)


class FindingFilterBar(Container):
    """Filter bar for security findings."""

    DEFAULT_CSS = """
    FindingFilterBar {
        layout: horizontal;
        height: auto;
        margin-bottom: 1;
        dock: top;
    }
    FindingFilterBar Input {
        width: 30;
        margin-right: 1;
    }
    FindingFilterBar .filter-group {
        layout: horizontal;
        height: auto;
    }
    FindingFilterBar Button {
        margin-right: 1;
        min-width: 10;
    }
    """

    def __init__(self, on_filter_change: Callable[[FindingFilters], None]):
        super().__init__()
        self._on_filter_change = on_filter_change
        self._search_input: Optional[Input] = None
        self._filter_buttons: Dict[str, Button] = {}

    def compose(self) -> ComposeResult:
        yield Input(
            placeholder="Search findings...", id="search-input", classes="search"
        )

        with Horizontal(classes="filter-group"):
            yield Button("🔴 Critical", id="filter-critical", variant="default")
            yield Button("🟠 High", id="filter-high", variant="default")
            yield Button("🟡 Medium", id="filter-medium", variant="default")
            yield Button("🟢 Low", id="filter-low", variant="default")
            yield Button("⚪ All", id="filter-all", variant="primary")

        yield Button("Clear Filters", id="clear-filters", variant="warning")

    def on_mount(self) -> None:
        """Store references to widgets."""
        self._search_input = self.query_one("#search-input", Input)
        self._filter_buttons = {
            "critical": self.query_one("#filter-critical", Button),
            "high": self.query_one("#filter-high", Button),
            "medium": self.query_one("#filter-medium", Button),
            "low": self.query_one("#filter-low", Button),
            "all": self.query_one("#filter-all", Button),
        }

    def on_input_changed(self, event) -> None:
        """Handle search input changes."""
        if hasattr(event, "input") and event.input and hasattr(event.input, "id"):
            if event.input.id == "search-input":
                self._notify_filter_change()

    def on_button_pressed(self, event) -> None:
        """Handle filter button presses."""
        button_id = getattr(getattr(event, "button", None), "id", None)

        if button_id == "clear-filters":
            self._clear_filters()
        elif button_id and button_id.startswith("filter-"):
            severity = button_id.replace("filter-", "")
            self._set_severity_filter(severity)

    def _clear_filters(self) -> None:
        """Clear all filters."""
        if self._search_input:
            self._search_input.value = ""
        for btn in self._filter_buttons.values():
            btn.variant = "default"

        filters = FindingFilters()
        self._on_filter_change(filters)

    def _set_severity_filter(self, severity: str) -> None:
        """Set severity filter and update button states."""
        # Reset all buttons
        for btn in self._filter_buttons.values():
            btn.variant = "default"

        # Set active button
        if severity in self._filter_buttons:
            self._filter_buttons[severity].variant = "primary"

        # Create filter
        filters = FindingFilters()
        if severity != "all":
            try:
                filters.severities = {Severity(severity)}
            except ValueError:
                pass

        self._on_filter_change(filters)

    def _notify_filter_change(self) -> None:
        """Notify parent of filter changes."""
        filters = FindingFilters()
        if self._search_input and self._search_input.value:
            filters.search_query = self._search_input.value
        self._on_filter_change(filters)


class FindingsTable(DataTable):
    """Enhanced data table for security findings."""

    DEFAULT_CSS = """
    FindingsTable {
        height: 100%;
        width: 100%;
    }
    FindingsTable .severity-critical {
        color: #ff6666;
    }
    FindingsTable .severity-high {
        color: #ffaa44;
    }
    FindingsTable .severity-medium {
        color: #ffdd44;
    }
    FindingsTable .severity-low {
        color: #66cc66;
    }
    FindingsTable .severity-informational {
        color: #888888;
    }
    FindingsTable .status-pass {
        color: #44ff44;
    }
    FindingsTable .status-fail {
        color: #ff4444;
    }
    FindingsTable .status-warning {
        color: #ffaa00;
    }
    """

    findings: reactive[List[SecurityFinding]] = reactive([])
    selected_finding: reactive[Optional[SecurityFinding]] = reactive(None)

    def __init__(
        self, on_selection: Optional[Callable[[SecurityFinding], None]] = None
    ):
        super().__init__()
        self._on_selection = on_selection
        self._sort_column = "severity"
        self._sort_reverse = True

    def watch_findings(self, findings: List[SecurityFinding]) -> None:
        """Update table when findings change."""
        self._refresh_table()

    def watch_selected_finding(self, finding: Optional[SecurityFinding]) -> None:
        """Handle finding selection."""
        if finding and self._on_selection:
            self._on_selection(finding)

    def _get_severity_order(self, severity: Severity) -> int:
        """Get numeric order for severity sorting."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }
        return order.get(severity, 99)

    def _get_status_order(self, status: Status) -> int:
        """Get numeric order for status sorting."""
        order = {
            Status.FAIL: 0,
            Status.WARNING: 1,
            Status.UNKNOWN: 2,
            Status.PASS: 3,
        }
        return order.get(status, 99)

    def _sort_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Sort findings by current sort column and direction."""
        return sorted(
            findings,
            key=lambda f: (
                self._get_severity_order(f.severity),
                self._get_status_order(f.status),
                f.check_id,
            ),
            reverse=self._sort_reverse,
        )

    def _get_severity_icon(self, severity: Severity) -> str:
        """Get icon for severity."""
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFORMATIONAL: "⚪",
        }
        return icons.get(severity, "⚪")

    def _get_status_icon(self, status: Status) -> str:
        """Get icon for status."""
        icons = {
            Status.PASS: "✅",
            Status.FAIL: "❌",
            Status.WARNING: "⚠️",
            Status.UNKNOWN: "❓",
        }
        return icons.get(status, "❓")

    def _format_row(self, finding: SecurityFinding) -> tuple:
        """Format a finding for display in the table."""
        severity_icon = self._get_severity_icon(finding.severity)
        status_icon = self._get_status_icon(finding.status)

        # Truncate description
        desc = (
            finding.description[:50] + "..."
            if len(finding.description) > 50
            else finding.description
        )

        return (
            f"{severity_icon} {finding.severity.value.upper()}",
            f"{status_icon} {finding.status.value}",
            finding.check_id[:25] if finding.check_id else "",
            finding.service[:15] if finding.service else "",
            finding.framework.value.upper() if finding.framework else "",
            desc,
        )

    def _refresh_table(self) -> None:
        """Refresh the table with current findings."""
        self.clear(columns=True)

        if not self.findings:
            self.add_column("Status", width=40)
            self.add_column("Check ID", width=30)
            self.add_column("Service", width=15)
            self.add_column("Description", width=60)
            return

        # Add columns
        self.add_column("Severity", width=15)
        self.add_column("Status", width=12)
        self.add_column("Check ID", width=28)
        self.add_column("Service", width=15)
        self.add_column("Framework", width=12)
        self.add_column("Description", width=50)

        # Sort and add rows
        sorted_findings = self._sort_findings(self.findings)
        for i, finding in enumerate(sorted_findings):
            row = self._format_row(finding)
            self.add_row(*row, key=str(i))

    def on_mount(self) -> None:
        """Initialize table on mount."""
        self._refresh_table()

    def on_data_table_row_selected(self, event) -> None:
        """Handle row selection."""
        if event.row_key is not None:
            sorted_findings = self._sort_findings(self.findings)
            if 0 <= event.row_key < len(sorted_findings):
                self.selected_finding = sorted_findings[event.row_key]

    def set_findings(self, findings: List[SecurityFinding]) -> None:
        """Set findings to display."""
        self.findings = findings

    def select_finding(self, finding: SecurityFinding) -> None:
        """Programmatically select a finding."""
        self.selected_finding = finding

    def clear_selection(self) -> None:
        """Clear current selection."""
        self.selected_finding = None

    def get_row_key_for_finding(self, finding: SecurityFinding) -> Optional[int]:
        """Get the row key for a specific finding."""
        sorted_findings = self._sort_findings(self.findings)
        for i, f in enumerate(sorted_findings):
            if f.check_id == finding.check_id and f.resource_id == finding.resource_id:
                return i
        return None


class FindingsPanel(Container):
    """Main panel for viewing and filtering security findings."""

    DEFAULT_CSS = """
    FindingsPanel {
        layout: vertical;
        height: 100%;
        width: 100%;
    }
    FindingsPanel FindingFilterBar {
        height: auto;
    }
    FindingsPanel FindingsTable {
        flex-grow: 1;
    }
    FindingsPanel .count-label {
        height: auto;
        margin-bottom: 1;
        padding: 0 1;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        store: SecurityStore,
        on_finding_select: Optional[Callable[[SecurityFinding], None]] = None,
    ):
        super().__init__()
        self._store = store
        self._on_finding_select = on_finding_select
        self._current_filters = FindingFilters()

    def compose(self) -> ComposeResult:
        yield Label("", id="finding-count", classes="count-label")
        yield FindingFilterBar(on_filter_change=self._on_filter_change)
        yield FindingsTable(id="findings-table", on_selection=self._on_finding_selected)

    def _on_filter_change(self, filters: FindingFilters) -> None:
        """Handle filter changes."""
        self._current_filters = filters
        self._refresh_findings()

    def _on_finding_selected(self, finding: SecurityFinding) -> None:
        """Handle finding selection."""
        if self._on_finding_select:
            self._on_finding_select(finding)

    def _refresh_findings(self) -> None:
        """Refresh findings based on current filters."""
        findings = self._store.get_filtered_findings(self._current_filters)

        # Update table
        table = self.query_one("#findings-table", FindingsTable)
        table.set_findings(findings)

        # Update count label
        count_label = self.query_one("#finding-count", Label)
        count_label.update(f"Showing {len(findings)} findings")

    def refresh_data(self) -> None:
        """Refresh all data."""
        self._store._get_security_data_sync()
        self._refresh_findings()

    def set_on_finding_select(
        self, callback: Callable[[SecurityFinding], None]
    ) -> None:
        """Set the callback for finding selection."""
        self._on_finding_select = callback
