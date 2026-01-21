import time
from typing import Dict, Optional
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TaskID,
)
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.style import Style


class ScanDashboard:
    def __init__(self, projects: list[str]):
        self.projects = sorted(projects)
        self.start_time = time.time()
        self.project_data: Dict[str, Dict] = {
            p: {"status": "Pending", "start": None, "end": None, "result": None}
            for p in projects
        }

        # Global Progress Bar
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=None, style="dim blue", complete_style="blue"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            "•",
            TimeElapsedColumn(),
            "•",
            TimeRemainingColumn(),
            expand=True,
        )
        self.task_id = self.progress.add_task("Overall Progress", total=len(projects))

        # Layout Setup
        self.layout = Layout()
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="metrics", size=8),
            Layout(name="table", ratio=1),
        )

        self.layout["header"].update(
            Panel(
                Text(
                    "🛡️  Fulcrum Security Scanner",
                    justify="center",
                    style="bold white on blue",
                ),
                style="blue",
            )
        )

    def update_project(
        self, project_id: str, status: str, result: Optional[bool] = None
    ):
        data = self.project_data[project_id]

        # State transitions
        if status == "Scanning" and data["status"] == "Pending":
            data["start"] = time.time()

        if result is not None:
            if data["end"] is None:
                data["end"] = time.time()
            data["result"] = result
            self.progress.advance(self.task_id)

        data["status"] = status

    def _get_metrics_grid(self) -> Table:
        total = len(self.projects)
        pending = sum(1 for p in self.project_data.values() if p["status"] == "Pending")
        scanning = sum(
            1 for p in self.project_data.values() if p["status"] == "Scanning"
        )
        completed = sum(
            1
            for p in self.project_data.values()
            if p["status"] in ["Done", "Error", "Timeout"]
        )
        success = sum(1 for p in self.project_data.values() if p["result"] is True)
        failed = completed - success

        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="center", ratio=1)

        grid.add_row(
            Text(f"Queue: {pending}", style="dim"),
            Text(f"Active: {scanning}", style="bold blue"),
            Text(f"Success: {success}", style="bold green"),
            Text(f"Failed: {failed}", style="bold red"),
        )
        return grid

    def _format_duration(self, start: Optional[float], end: Optional[float]) -> str:
        if not start:
            return "-"

        current_end = end if end else time.time()
        duration = current_end - start

        if duration < 60:
            return f"{duration:.1f}s"
        return f"{duration / 60:.1f}m"

    def _generate_table(self) -> Table:
        table = Table(expand=True, border_style="dim", box=None, padding=(0, 2))
        table.add_column("Project", style="cyan bold")
        table.add_column("Status", width=12)
        table.add_column("Duration", justify="right", width=10)
        table.add_column("Details", style="dim", ratio=1)

        # Sort: Scanning first, then Pending, then Done/Error
        def sort_key(p):
            s = self.project_data[p]["status"]
            order = {"Scanning": 0, "Pending": 1, "Done": 2, "Error": 3, "Timeout": 4}
            return (order.get(s, 5), p)

        for project in sorted(self.projects, key=sort_key):
            data = self.project_data[project]
            status = data["status"]

            # Status & Icon
            if status == "Pending":
                status_render = Text("● Pending", style="dim")
                details = ""
            elif status == "Scanning":
                status_render = Text("⚡ Scanning", style="blue bold")
                details = "Running checks..."
            elif status == "Done":
                status_render = Text("✔ Done", style="green")
                details = "Report generated"
            elif status == "Error":
                status_render = Text("✖ Error", style="red")
                details = "See logs"
            elif status == "Timeout":
                status_render = Text("⏱ Timeout", style="yellow")
                details = "Exceeded limit"
            else:
                status_render = Text(status)
                details = ""

            duration = self._format_duration(data["start"], data["end"])

            table.add_row(project, status_render, duration, details)

        return table

    def get_renderable(self):
        # Update metrics layout
        self.layout["metrics"].update(
            Panel(
                Group(
                    self.progress,
                    Text(" "),  # Spacer
                    self._get_metrics_grid(),
                ),
                border_style="dim",
            )
        )

        # Update table
        self.layout["table"].update(
            Panel(self._generate_table(), title="Active Scans", border_style="blue")
        )
        return self.layout
