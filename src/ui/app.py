"""
Modernized TUI Dashboard with Workers and State Management.

Features:
- Centralized data store with reactive properties and caching
- Async operations without blocking the UI
- Data caching for instant view switches
- Proper error notifications
- Security dashboard with findings, compliance, and remediation
"""

import asyncio
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from enum import Enum

from textual.app import App, ComposeResult
from textual.widgets import (
    Header,
    Footer,
    DataTable,
    Static,
    LoadingIndicator,
    Container,
)
from textual.reactive import reactive


class ViewState(Enum):
    """Current view state of the dashboard."""

    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORKING = "networking"
    KUBERNETES = "kubernetes"
    SECURITY = "security"
    EXECUTIVE = "executive"


@dataclass
class TableData:
    """Cached table data with metadata."""

    headers: List[str] = field(default_factory=list)
    rows: List[List[str]] = field(default_factory=list)
    path: str = ""
    loaded_at: float = 0.0
    valid_for_seconds: int = 300  # 5 minutes cache TTL


class DataStore:
    """
    Centralized data store with reactive properties and caching.

    Provides:
    - Automatic caching of loaded data
    - Cache invalidation based on TTL
    """

    def __init__(self, out_dir: str):
        self.out_dir = out_dir
        self._cache: Dict[str, TableData] = {}
        self._callbacks: List[Callable] = []
        self._loading: Dict[str, bool] = {}

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

    def get_csv_path(self, view: ViewState) -> str:
        """Get the CSV file path for a given view."""
        mapping = {
            ViewState.COMPUTE: "compute.csv",
            ViewState.STORAGE: "storage.csv",
            ViewState.NETWORKING: "networking.csv",
            ViewState.KUBERNETES: "kubernetes.csv",
            ViewState.SECURITY: "security.csv",
        }
        filename = mapping.get(view, "compute.csv")
        return os.path.join(self.out_dir, "csv", filename)

    def is_cache_valid(self, view: ViewState) -> bool:
        """Check if cached data for view is still valid."""
        path = self.get_csv_path(view)
        if path not in self._cache:
            return False
        import time

        data = self._cache[path]
        return (time.time() - data.loaded_at) < data.valid_for_seconds

    def load_table_data(self, view: ViewState) -> TableData:
        """Load table data from CSV file with caching."""
        path = self.get_csv_path(view)
        import time

        # Check cache first
        if path in self._cache:
            data = self._cache[path]
            if (time.time() - data.loaded_at) < data.valid_for_seconds:
                return data

        # Load from file
        rows: List[List[str]] = []
        headers: List[str] = []

        if os.path.exists(path):
            with open(path) as f:
                for i, line in enumerate(f):
                    cols = line.rstrip().split(",")
                    if i == 0:
                        headers = cols
                    else:
                        rows.append(cols)

        data = TableData(
            headers=headers,
            rows=rows[:100],  # Limit rows for performance
            path=path,
            loaded_at=time.time(),
        )
        self._cache[path] = data
        self._notify()
        return data

    def clear_cache(self) -> None:
        """Clear all cached data."""
        self._cache.clear()
        self._notify()

    def invalidate_view(self, view: ViewState) -> None:
        """Invalidate cached data for a specific view."""
        path = self.get_csv_path(view)
        if path in self._cache:
            del self._cache[path]
            self._notify()


class Dashboard(App):
    """
    Modernized TUI Dashboard with State Management.

    Features:
    - Reactive state management via DataStore
    - Data caching for instant view switches
    - Async subprocess execution
    - Proper error notifications
    """

    CSS = """
    Screen {
        layout: grid;
        grid-size: 1 3;
    }
    Static {
        height: auto;
        padding: 1;
    }
    DataTable {
        height: 100%;
    }
    LoadingIndicator {
        dock: bottom;
    }
    """

    current_view: reactive[ViewState] = reactive(ViewState.COMPUTE)
    is_loading: reactive[bool] = reactive(False)
    loading_message: reactive[str] = reactive("")

    def __init__(self, out_dir: str):
        super().__init__()
        self.out_dir = out_dir
        self.store = DataStore(out_dir)
        self.store.register_callback(self._on_store_change)
        self._notification: Optional[Static] = None
        self._executive_task: Optional[asyncio.Task] = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Fulcrum Dashboard", id="title")
        yield DataTable(id="data_table")
        yield Footer()
        yield LoadingIndicator(id="loading")

    def on_mount(self) -> None:
        """Initialize the dashboard."""
        self.store.load_table_data(ViewState.COMPUTE)
        self._update_table(ViewState.COMPUTE)
        self._show_help()

    def _on_store_change(self) -> None:
        """Handle data store changes."""
        self._update_table(self.current_view)

    def _set_loading(self, loading: bool, message: str = "") -> None:
        """Set loading state."""
        self.is_loading = loading
        self.loading_message = message
        loading_widget = self.query_one("#loading", LoadingIndicator)
        if loading:
            loading_widget.display = True
        else:
            loading_widget.display = False

    def _show_help(self) -> None:
        """Show help message."""
        help_text = (
            "Press keys to switch views:\n"
            "  [b]c[/] - Compute | [b]s[/] - Storage | [b]n[/] - Networking\n"
            "  [b]k[/] - Kubernetes | [b]e[/] - Executive Report\n"
            "  [b]?[/] - Show this help"
        )
        self.mount(Static(help_text, id="help"))

    def _update_table(self, view: ViewState) -> None:
        """Update the data table for the current view."""
        table = self.query_one(DataTable)
        data = self.store.load_table_data(view)

        if data and data.headers:
            table.clear(columns=True)
            table.add_columns(*data.headers)
            for row in data.rows:
                table.add_row(*row)
        elif data:
            table.clear(columns=True)

    def _show_notification(self, message: str, severity: str = "info") -> None:
        """Show a notification message."""
        style = {
            "success": "green",
            "error": "red",
            "warning": "yellow",
            "info": "cyan",
        }.get(severity, "white")

        # Remove old notification
        if self._notification:
            self._notification.remove()

        self._notification = Static(
            f"[{style}]{message}[/]",
            id="notification",
        )
        self.mount(self._notification)

        # Auto-dismiss after 5 seconds
        async def dismiss():
            await asyncio.sleep(5)
            if self._notification:
                self._notification.remove()
                self._notification = None

        asyncio.create_task(dismiss())

    async def _generate_executive_report_async(self) -> None:
        """Generate executive report asynchronously."""
        try:
            self._set_loading(True, "Generating executive report...")

            from ..core.settings import load_settings
            from ..core.docs import (
                generate_project_tables,
                generate_kubernetes_docs,
                build_index,
                write_metadata,
                generate_kubernetes_csv,
                generate_asset_summaries,
                generate_used_services_summary,
            )

            s = load_settings(None)

            # Get author from catalog or use default
            author = s.catalog.projects[0] if s.catalog.projects else "Fulcrum"
            version = "1.0.0"
            org_id = s.org.org_id or ""

            # Generate all documentation
            generate_project_tables(self.out_dir)
            generate_kubernetes_docs(self.out_dir, author)
            generate_kubernetes_csv(self.out_dir)
            generate_asset_summaries(self.out_dir)
            generate_used_services_summary(self.out_dir)
            build_index(
                self.out_dir,
                author,
                {},
                {"summary": "kubernetes/catalog.md"},
            )
            write_metadata(self.out_dir, author, version, org_id, s.catalog.projects)

            self._show_notification(
                f"Executive report generated: {self.out_dir}",
                "success",
            )
            # Invalidate cache for executive views
            self.store.invalidate_view(ViewState.EXECUTIVE)

        except Exception as e:
            self._show_notification(
                f"Failed to generate report: {e}",
                "error",
            )
        finally:
            self._set_loading(False)
            self._executive_task = None

    async def on_key(self, event) -> None:
        """Handle key presses."""
        key = getattr(event, "key", "").lower()

        if key == "c":
            self.current_view = ViewState.COMPUTE
            self._update_table(ViewState.COMPUTE)
        elif key == "s":
            self.current_view = ViewState.STORAGE
            self._update_table(ViewState.STORAGE)
        elif key == "n":
            self.current_view = ViewState.NETWORKING
            self._update_table(ViewState.NETWORKING)
        elif key == "k":
            self.current_view = ViewState.KUBERNETES
            self._update_table(ViewState.KUBERNETES)
        elif key == "e":
            # Check if already running
            if self._executive_task and not self._executive_task.done():
                self._show_notification(
                    "Report generation already in progress",
                    "warning",
                )
                return
            # Start async task
            self._executive_task = asyncio.create_task(
                self._generate_executive_report_async()
            )
        elif key == "?":
            self._show_help()
            return

        # Remove help text on first navigation
        help_widget = self.query_one("#help", Static)
        if help_widget:
            help_widget.remove()


def launch(out_dir: str) -> None:
    """Launch the modernized TUI dashboard."""
    app = Dashboard(out_dir)
    app.run()
