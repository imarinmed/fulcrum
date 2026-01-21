"""
Unified Report Builder with Strategy Pattern.

Consolidates dual report generation paths (standard and executive) into a single
architecture with swappable strategies.

Classes:
- ReportStrategy: Abstract base for report generation strategies
- StandardReportStrategy: Standard GCP catalog format
- ExecutiveReportStrategy: Executive documentation format
- ReportBuilder: Unified builder that orchestrates report generation
"""

import csv
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    output_dir: str = "reports"
    report_date: Optional[str] = None
    report_type: str = "std"
    author: str = ""
    version: str = "1.0.0"


@dataclass
class ReportResult:
    """Result of report generation."""
    output_dir: str
    index_path: str
    metadata_path: str
    pages: Dict[str, str] = field(default_factory=dict)
    data_files: Dict[str, str] = field(default_factory=dict)


class ReportStrategy(ABC):
    """Abstract base class for report generation strategies."""

    def __init__(self, config: ReportConfig):
        self.config = config

    @abstractmethod
    def get_output_subdir(self) -> str:
        """Get subdirectory name for this report type."""
        pass

    @abstractmethod
    def format_page(self, name: str, headers: List[str], rows: List[List[str]]) -> str:
        """Format a page with headers and rows."""
        pass

    @abstractmethod
    def format_index(self, pages: Dict[str, str], author: str) -> str:
        """Format the report index."""
        pass

    @abstractmethod
    def get_project_filename(self, name: str) -> str:
        """Get filename for a project page."""
        pass

    def ensure_output_dir(self, base: Optional[str] = None) -> str:
        """Ensure output directory exists and return its path."""
        out_base = base or self.config.output_dir
        date_str = self.config.report_date or datetime.now(timezone.utc).strftime("%Y%m%d")
        report_type = self.config.report_type

        # Build directory name: {base}/report-{type}-{date}
        parent = os.path.join(out_base, f"report-{report_type}-{date_str}")

        # Handle duplicate directories
        if os.path.isdir(parent):
            try:
                if any(True for _ in os.scandir(parent)):
                    suffix = 2
                    while True:
                        candidate = f"{parent}-{suffix:02d}"
                        if not os.path.exists(candidate):
                            parent = candidate
                            break
                        suffix += 1
            except OSError as e:
                log.warning(
                    "report_builder.scandir_error",
                    path=parent,
                    error=str(e),
                    security_event=True
                )
                suffix = 2
                while True:
                    candidate = f"{parent}-{suffix:02d}"
                    if not os.path.exists(candidate):
                        parent = candidate
                        break
                    suffix += 1

        os.makedirs(parent, exist_ok=True)
        os.makedirs(os.path.join(parent, "projects"), exist_ok=True)
        os.makedirs(os.path.join(parent, "data"), exist_ok=True)
        return parent

    def read_csv(self, path: str) -> Tuple[List[str], List[List[str]]]:
        """Read CSV file and return headers and rows."""
        if not os.path.exists(path):
            return [], []
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            headers = list(reader.fieldnames or [])
            rows: List[List[str]] = []
            for r in reader:
                rows.append([str(r.get(h, "")) for h in headers])
            return headers, rows

    def read_csv_dict(self, path: str) -> List[Dict[str, str]]:
        """Read CSV file and return list of dicts."""
        if not os.path.exists(path):
            return []
        with open(path, newline="") as f:
            return list(csv.DictReader(f))

    def write_md(self, path: str, content: str) -> None:
        """Write markdown content to file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)

    def write_json(self, path: str, data: Any) -> None:
        """Write JSON data to file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def write_csv(self, path: str, headers: List[str], rows: List[List[str]]) -> None:
        """Write CSV file from headers and rows."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)


class StandardReportStrategy(ReportStrategy):
    """Standard GCP catalog report format."""

    def get_output_subdir(self) -> str:
        return "projects"

    def format_page(self, name: str, headers: List[str], rows: List[List[str]]) -> str:
        """Format a standard report page with table."""
        from .markdown import header, table

        content = header(2, name.replace("_", " ").title())
        if headers:
            content += table(headers, rows)
        else:
            content += "No data available\n"
        return content

    def format_index(self, pages: Dict[str, str], author: str) -> str:
        """Format the standard report index."""
        from .markdown import header, link, escape

        lines: List[str] = []
        lines.append(header(2, "Report Overview"))
        lines.append(f"Author: {escape(author)}\n\n")
        lines.append(header(3, "Contents"))

        for name in [
            "compute",
            "data_storage",
            "data_analytics",
            "networking",
            "kubernetes",
            "security",
            "serverless",
            "virtual_machines",
            "storage",
            "buckets",
        ]:
            if name in pages:
                rel = os.path.relpath(pages[name], self.config.output_dir)
                lines.append(f"- {link(name.replace('_', ' ').title(), rel})")

        return "".join(lines)

    def get_project_filename(self, name: str) -> str:
        return f"{name}.md"


class ExecutiveReportStrategy(ReportStrategy):
    """Executive documentation format with project-focused tables."""

    def get_output_subdir(self) -> str:
        return "projects"

    def format_page(self, name: str, headers: List[str], rows: List[List[str]]) -> str:
        """Format an executive page with enhanced headers."""
        from .markdown import table

        title = name.replace("_", " ").title()
        content = f"# {title}\n\n"
        if headers:
            content += table(headers, rows)
        else:
            content += "No data available\n"
        return content

    def format_index(self, pages: Dict[str, str], author: str) -> str:
        """Format the executive report index."""
        lines: List[str] = []
        lines.append("# Project Documentation Index\n\n")
        lines.append(f"Author: {author}\n")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
        lines.append("## Table of Contents\n")

        for name, path in sorted(pages.items()):
            rel = os.path.relpath(path, self.config.output_dir)
            lines.append(f"- [{name.replace('_', ' ').title()}]({rel})")

        return "\n".join(lines)

    def get_project_filename(self, name: str) -> str:
        return f"{name}.md"


class FinOpsReportStrategy(ReportStrategy):
    """FinOps report strategy for cost analysis and optimization."""
    
    def get_output_subdir(self) -> str:
        return "finops"

    def format_page(self, name: str, headers: List[str], rows: List[List[str]]) -> str:
        """Format a FinOps report page."""
        from .markdown import header, table
        
        title = name.replace("_", " ").title()
        content = header(2, title)
        if headers:
            content += table(headers, rows)
        else:
            content += "No data available\n"
        return content

    def format_index(self, pages: Dict[str, str], author: str) -> str:
        """Format the FinOps report index."""
        from .markdown import header, link, escape
        
        lines: List[str] = []
        lines.append(header(2, "FinOps Report Overview"))
        lines.append(f"Author: {escape(author)}\n")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
        lines.append(header(3, "Contents"))
        
        # Add cost summary
        lines.append(header(3, "Cost Summary"))
        
        # Add recommendations if available
        if "recommendations" in pages:
            rel = os.path.relpath(pages["recommendations"], self.config.output_dir)
            lines.append(f"- [Cost Optimization Recommendations]({rel})")
        
        # Add GKE costs if available
        if "gke_costs" in pages:
            rel = os.path.relpath(pages["gke_costs"], self.config.output_dir)
            lines.append(f"- [GKE Cost Analysis]({rel})")
        
        # Add other pages
        for name in sorted(pages.keys()):
            if name not in ["recommendations", "gke_costs"]:
                rel = os.path.relpath(pages[name], self.config.output_dir)
                lines.append(f"- [{name.replace('_', ' ').title()}]({rel})")
        
        return "\n".join(lines)

    def get_project_filename(self, name: str) -> str:
        return f"{name}.md"


class ReportBuilder:
    """
    Unified report builder with strategy pattern.

    Consolidates CSV reading, markdown generation, and directory management
    into a single interface with swappable output formats.
    """

    STRATEGIES: Dict[str, Type[ReportStrategy]] = {
        "std": StandardReportStrategy,
        "sec": StandardReportStrategy,
        "executive": ExecutiveReportStrategy,
        "finops": "FinOpsReportStrategy",  # Lazy reference for now
    }

    def __init__(self, strategy: Optional[ReportStrategy] = None):
        self.strategy = strategy or StandardReportStrategy(ReportConfig())

    def set_strategy(self, strategy: ReportStrategy) -> "ReportBuilder":
        """Set the report generation strategy."""
        self.strategy = strategy
        return self

    def with_config(self, config: ReportConfig) -> "ReportBuilder":
        """Configure the report builder."""
        self.strategy.config = config
        return self

    def ensure_output_dir(self) -> str:
        """Ensure output directory exists."""
        return self.strategy.ensure_output_dir()

    def read_csv(self, path: str) -> Tuple[List[str], List[List[str]]]:
        """Read CSV file."""
        return self.strategy.read_csv(path)

    def read_csv_dict(self, path: str) -> List[Dict[str, str]]:
        """Read CSV file as list of dicts."""
        return self.strategy.read_csv_dict(path)

    def write_page(
        self, output_dir: str, name: str, headers: List[str], rows: List[List[str]]
    ) -> str:
        """Write a report page and return its path."""
        content = self.strategy.format_page(name, headers, rows)
        subdir = self.strategy.get_output_subdir()
        filename = self.strategy.get_project_filename(name)
        path = os.path.join(output_dir, subdir, filename)
        self.strategy.write_md(path, content)
        return path

    def write_index(self, output_dir: str, pages: Dict[str, str]) -> str:
        """Write report index and return its path."""
        content = self.strategy.format_index(pages, self.strategy.config.author)
        path = os.path.join(output_dir, "index.md")
        self.strategy.write_md(path, content)
        return path

    def write_metadata(
        self, output_dir: str, org_id: str, projects: List[str]
    ) -> str:
        """Write report metadata and return its path."""
        meta = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_version": self.strategy.config.version,
            "org_id": org_id,
            "projects": projects,
        }
        path = os.path.join(output_dir, "metadata.json")
        self.strategy.write_json(path, meta)
        return path

    def write_data_file(self, output_dir: str, name: str, data: Any) -> str:
        """Write a data file (JSON/CSV) and return its path."""
        path = os.path.join(output_dir, "data", name)
        if isinstance(data, (dict, list)):
            self.strategy.write_json(path, data)
        else:
            self.strategy.write_csv(*data) if isinstance(data, tuple) else None
        return path

    def build(self, config: ReportConfig) -> ReportResult:
        """Build a report using the configured strategy."""
        output_dir = self.strategy.ensure_output_dir(config.output_dir)

        pages: Dict[str, str] = {}
        data_files: Dict[str, str] = {}

        return ReportResult(
            output_dir=output_dir,
            index_path=self.write_index(output_dir, pages),
            metadata_path=self.write_metadata(output_dir, "", []),
            pages=pages,
            data_files=data_files,
        )
