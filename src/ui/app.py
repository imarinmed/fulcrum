from typing import List
import asyncio
import os
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static
import os, sys


def load_table_rows(path: str) -> List[List[str]]:
    rows: List[List[str]] = []
    if os.path.exists(path):
        with open(path) as f:
            for i, line in enumerate(f):
                cols = line.rstrip().split(",")
                rows.append(cols)
    return rows


class Dashboard(App):
    CSS = "Screen {layout: grid; grid-size: 1 3}"

    def __init__(self, out_dir: str):
        super().__init__()
        self.out_dir = out_dir

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Inventory")
        yield DataTable()
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        rows = load_table_rows(os.path.join(self.out_dir, "csv", "compute.csv"))
        if rows:
            table.add_columns(*rows[0])
            for r in rows[1:100]:
                table.add_row(*r)

    async def on_key(self, event) -> None:
        if getattr(event, "key", "").lower() == "e":
            env = dict(os.environ)
            exec_out = os.path.join(self.out_dir, "executive")
            env["EXEC_OUT"] = exec_out
            script_path = os.path.join(
                self.out_dir, "scripts", "build_executive_report.py"
            )
            # Use asyncio.create_subprocess_exec instead of blocking subprocess.run
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                script_path,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                self.mount(Static(f"Error generating report: {stderr.decode()}"))
            else:
                self.mount(Static(f"Executive report generated in {exec_out}"))
        if getattr(event, "key", "").lower() == "d":
            from fulcrum.core.settings import load_settings

            s = load_settings(None)
            from fulcrum.core.docs import (
                generate_project_tables,
                generate_kubernetes_docs,
                build_index,
                write_metadata,
                generate_kubernetes_csv,
                generate_asset_summaries,
                generate_used_services_summary,
            )

            generate_project_tables(self.out_dir)
            generate_kubernetes_docs(self.out_dir, s.metadata.author)
            generate_kubernetes_csv(self.out_dir)
            generate_asset_summaries(self.out_dir)
            generate_used_services_summary(self.out_dir)
            build_index(
                self.out_dir,
                s.metadata.author,
                {},
                {"summary": "kubernetes/catalog.md"},
            )
            write_metadata(
                self.out_dir,
                s.metadata.author,
                s.metadata.version,
                s.org.org_id,
                s.catalog.projects,
            )
            self.mount(Static("Project documentation generated under executive/"))
        if getattr(event, "key", "").lower() == "k":
            table = self.query_one(DataTable)
            table.clear(columns=True)
            rows = load_table_rows(os.path.join(self.out_dir, "csv", "kubernetes.csv"))
            if rows:
                table.add_columns(*rows[0])
                for r in rows[1:100]:
                    table.add_row(*r)


def launch(out_dir: str) -> None:
    app = Dashboard(out_dir)
    app.run()
