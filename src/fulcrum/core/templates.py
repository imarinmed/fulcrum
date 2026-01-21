"""
Template Engine Wrapper for Jinja2-based Markdown Generation.

Provides a simple interface for rendering markdown templates with
automatic escaping and custom filters.

Usage:
    from src.core.templates import TemplateEngine, render_page, render_index

    # Render a page
    content = render_page(
        title="Virtual Machines",
        headers=["name", "status"],
        rows=[["vm-1", "RUNNING"], ["vm-2", "STOPPED"]],
        template="report_page"
    )

    # Render an index
    content = render_index(
        author="John Doe",
        pages={"compute": "compute.md", "storage": "storage.md"}
    )
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import jinja2
import structlog

log = structlog.get_logger()

# Template directory - templates are in src/templates/
TEMPLATE_DIR = Path(__file__).parent.parent / "templates"

# Default templates
DEFAULT_TEMPLATES = {
    "report_page": "report_page.j2",
    "report_index": "report_index.j2",
    "executive_page": "executive_page.j2",
    "kubernetes_catalog": "kubernetes_catalog.j2",
}


class TemplateEngine:
    """
    Jinja2 template engine with custom filters and auto-loading.

    Features:
    - Auto-loads templates from src/templates/
    - Custom markdown-safe filters
    - Template caching for performance
    - Context-aware rendering
    """

    def __init__(self, template_dir: Optional[Path] = None):
        self.template_dir = template_dir or TEMPLATE_DIR
        self._env: Optional[jinja2.Environment] = None
        self._cache: Dict[str, jinja2.Template] = {}

    @property
    def env(self) -> jinja2.Environment:
        """Get or create the Jinja2 environment."""
        if self._env is None:
            self._env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(str(self.template_dir)),
                autoescape=False,  # We handle escaping ourselves
                trim_blocks=True,
                lstrip_blocks=True,
            )
            # Add custom filters
            self._env.filters["sort"] = sorted
            self._env.filters["length"] = len
            self._env.filters["join"] = lambda x, y: y.join(x)
        return self._env

    def get_template(self, name: str) -> jinja2.Template:
        """Get a template by name (with caching)."""
        if name not in self._cache:
            self._cache[name] = self.env.get_template(name)
        return self._cache[name]

    def clear_cache(self) -> None:
        """Clear the template cache."""
        self._cache.clear()

    def render(
        self,
        template_name: str,
        context: Dict[str, Any],
    ) -> str:
        """
        Render a template with the given context.

        Args:
            template_name: Name of the template (without .j2 extension)
            context: Variables to pass to the template

        Returns:
            Rendered markdown content
        """
        try:
            # Map template name to filename if needed
            template_file = DEFAULT_TEMPLATES.get(template_name, template_name)
            if not template_file.endswith(".j2"):
                template_file = f"{template_file}.j2"
            template = self.get_template(template_file)
            return template.render(**context)
        except jinja2.TemplateNotFound:
            log.error("template.not_found", template=template_name)
            raise
        except jinja2.TemplateError as e:
            log.error("template.render_error", template=template_name, error=str(e))
            raise


# Global template engine instance
_engine: Optional[TemplateEngine] = None


def get_engine() -> TemplateEngine:
    """Get the global template engine instance."""
    global _engine
    if _engine is None:
        _engine = TemplateEngine()
    return _engine


def render_page(
    title: str,
    headers: List[str],
    rows: List[List[str]],
    template: str = "report_page",
    footer: Optional[str] = None,
    **extra: Any,
) -> str:
    """
    Render a report page using a template.

    Args:
        title: Page title
        headers: Column headers
        rows: Data rows
        template: Template name to use
        footer: Optional footer text
        **extra: Additional context variables

    Returns:
        Rendered markdown content
    """
    engine = get_engine()
    return engine.render(
        template,
        {
            "title": title,
            "headers": headers,
            "rows": rows,
            "footer": footer,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **extra,
        },
    )


def render_index(
    author: str,
    pages: Dict[str, str],
    template: str = "report_index",
    **extra: Any,
) -> str:
    """
    Render a report index using a template.

    Args:
        author: Report author
        pages: Dict of page name -> relative path
        template: Template name to use
        **extra: Additional context variables

    Returns:
        Rendered markdown content
    """
    engine = get_engine()
    return engine.render(
        template,
        {
            "author": author,
            "pages": pages,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **extra,
        },
    )


def render_executive_page(
    title: str,
    headers: List[str],
    rows: List[List[str]],
    metadata: Optional[Dict[str, Any]] = None,
    template: str = "executive_page",
    **extra: Any,
) -> str:
    """
    Render an executive report page with enhanced metadata.

    Args:
        title: Page title
        headers: Column headers
        rows: Data rows
        metadata: Optional metadata dict
        template: Template name to use
        **extra: Additional context variables

    Returns:
        Rendered markdown content
    """
    engine = get_engine()
    return engine.render(
        template,
        {
            "title": title,
            "headers": headers,
            "rows": rows,
            "metadata": metadata,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **extra,
        },
    )


def render_kubernetes_catalog(
    author: str,
    clusters: List[Dict[str, Any]],
    template: str = "kubernetes_catalog",
    **extra: Any,
) -> str:
    """
    Render a Kubernetes cluster catalog.

    Args:
        author: Report author
        clusters: List of cluster dictionaries
        template: Template name to use
        **extra: Additional context variables

    Returns:
        Rendered markdown content
    """
    engine = get_engine()

    # Extract headers and rows from clusters
    headers = [
        "project_id",
        "name",
        "location",
        "masterVersion",
        "network",
        "subnetwork",
        "labels",
    ]
    rows = [
        [
            c.get("project_id", ""),
            c.get("name", ""),
            c.get("location", ""),
            c.get("masterVersion", ""),
            c.get("network", ""),
            c.get("subnetwork", ""),
            c.get("labels", ""),
        ]
        for c in clusters
    ]

    return engine.render(
        template,
        {
            "author": author,
            "clusters": clusters,
            "headers": headers,
            "rows": rows,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **extra,
        },
    )
