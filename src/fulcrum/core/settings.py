import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field
import tomlkit
import structlog

log = structlog.get_logger()


class SecurityError(Exception):
    """Raised when security checks fail."""

    pass


# Allowed config file locations (for path traversal prevention)
ALLOWED_CONFIG_DIRS = [
    Path.cwd(),
    Path.home() / ".config" / "fulcrum",
    Path("/etc/fulcrum"),
]


def _is_path_safe(requested_path: Path, allowed_dirs: List[Path]) -> bool:
    """
    Check if a path is within allowed directories.

    Args:
        requested_path: Path to validate
        allowed_dirs: List of allowed base directories

    Returns:
        True if path is safe, False otherwise
    """
    try:
        resolved = requested_path.resolve()
        for allowed in allowed_dirs:
            allowed_resolved = allowed.resolve()
            # Check if resolved path starts with allowed directory
            try:
                resolved.relative_to(allowed_resolved)
                return True
            except ValueError:
                continue
        return False
    except (OSError, ValueError):
        return False


def safe_resolve_config(path: Optional[str]) -> Optional[Path]:
    """
    Resolve config path with security validation.

    Args:
        path: Requested config path or None

    Returns:
        Resolved Path if safe, None otherwise
    """
    if not path:
        return None

    requested = Path(path)

    if not _is_path_safe(requested, ALLOWED_CONFIG_DIRS):
        log.error(
            "settings.path_traversal_attempt", path=str(requested), security_event=True
        )
        raise SecurityError(
            f"Config path outside allowed directories: {path}. "
            f"Allowed directories: {[str(d) for d in ALLOWED_CONFIG_DIRS]}"
        )

    return requested


class OrgSettings(BaseModel):
    org_id: str = ""
    folder_ids: List[str] = Field(default_factory=list)


class CatalogSettings(BaseModel):
    projects: List[str] = Field(default_factory=list)
    timeout_sec: int = 60
    limit_per_project: int = 500


class BillingSettings(BaseModel):
    export_dataset: str = "billing_export"


class LabelsSettings(BaseModel):
    owner: List[str] = Field(
        default_factory=lambda: ["owner", "owner_name", "managed_by"]
    )
    cost_center: List[str] = Field(
        default_factory=lambda: ["cost_center", "cc", "costcentre"]
    )
    env: List[str] = Field(default_factory=lambda: ["env", "environment"])


class RedactionSettings(BaseModel):
    enabled: bool = True


class RefreshSettings(BaseModel):
    cadence: str = "weekly"


class DecommissionSettings(BaseModel):
    """Settings for decommission operations."""

    bucket_whitelist: List[str] = Field(
        default_factory=list,
        description="List of bucket names to preserve during decommissioning",
    )


class Settings(BaseModel):
    org: OrgSettings = OrgSettings()
    catalog: CatalogSettings = CatalogSettings()
    billing: BillingSettings = BillingSettings()
    labels: LabelsSettings = LabelsSettings()
    redaction: RedactionSettings = RedactionSettings()
    refresh: RefreshSettings = RefreshSettings()

    class CredentialsSettings(BaseModel):
        sa_key_path: Optional[str] = None
        impersonate_service_account: Optional[str] = None
        quota_project: Optional[str] = None

    credentials: CredentialsSettings = CredentialsSettings()

    class SecuritySettings(BaseModel):
        prowler_bin: str = "assets/prowler/prowler"
        api_url: str = ""
        api_token: str = ""
        timeout_sec: int = 600

    security: SecuritySettings = SecuritySettings()

    class ReportsSettings(BaseModel):
        out_base: str = "reports"
        formats: List[str] = Field(default_factory=lambda: ["md", "json", "csv"])
        default_date: str = "now"

    reports: ReportsSettings = ReportsSettings()

    class OutputSettings(BaseModel):
        base_dir: str = "master-report"
        summary_path: str = ""
        slides_dir: str = ""
        csv_dir: str = ""
        access_dir: str = ""
        raw_dir: str = ""

    output: OutputSettings = OutputSettings()

    decommission: DecommissionSettings = Field(default_factory=DecommissionSettings)

    class MetadataSettings(BaseModel):
        author: str = "Iñaki Marín"
        version: str = "fulcrum 0.1.0"

    metadata: MetadataSettings = MetadataSettings()


def default_paths() -> List[str]:
    paths: List[str] = []
    cwd = os.getcwd()
    paths.append(os.path.join(cwd, "fulcrum.toml"))
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    paths.append(os.path.join(xdg, "fulcrum", "fulcrum.toml"))
    return paths


def locate_config(explicit: Optional[str] = None) -> Optional[str]:
    """Locate config file with path traversal protection.

    Args:
        explicit: Explicit config path if provided

    Returns:
        Config path or None if not found
    """
    try:
        # If explicit path provided, validate it
        if explicit:
            safe_path = safe_resolve_config(explicit)
            if safe_path and os.path.exists(safe_path):
                return str(safe_path)
            else:
                return None

        # Check default paths
        for p in default_paths():
            safe_path = safe_resolve_config(p)
            if safe_path and os.path.exists(safe_path):
                return str(safe_path)

        return None
    except SecurityError as e:
        log.error(
            "settings.config_path_rejected",
            path=explicit,
            error=str(e),
            security_event=True,
        )
        return None


def load_settings(path: Optional[str] = None) -> Settings:
    """Load settings with security validation.

    Args:
        path: Optional explicit config path

    Returns:
        Settings object
    """
    cfg_path = locate_config(path)
    if cfg_path and os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r") as f:
                data = tomlkit.parse(f.read())
            return Settings(
                org=OrgSettings(**data.get("org", {})),
                catalog=CatalogSettings(**data.get("catalog", {})),
                billing=BillingSettings(**data.get("billing", {})),
                labels=LabelsSettings(**data.get("labels", {})),
                redaction=RedactionSettings(**data.get("redaction", {})),
                refresh=RefreshSettings(**data.get("refresh", {})),
                credentials=Settings.CredentialsSettings(**data.get("credentials", {})),
                security=Settings.SecuritySettings(**data.get("security", {})),
                reports=Settings.ReportsSettings(**data.get("reports", {})),
                output=Settings.OutputSettings(**data.get("output", {})),
                metadata=Settings.MetadataSettings(**data.get("metadata", {})),
                decommission=DecommissionSettings(**data.get("decommission", {})),
            )
        except (OSError, IOError, Exception) as e:
            log.error(
                "settings.load_error", path=cfg_path, error=str(e), security_event=True
            )
            return Settings()
    return Settings()


def save_settings(path: Optional[str], s: Settings) -> str:
    cfg_path = locate_config(path)
    os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
    doc = tomlkit.document()
    doc.add("org", tomlkit.table())
    doc["org"]["org_id"] = s.org.org_id
    doc["org"]["folder_ids"] = s.org.folder_ids
    doc.add("catalog", tomlkit.table())
    doc["catalog"]["projects"] = s.catalog.projects
    doc["catalog"]["timeout_sec"] = s.catalog.timeout_sec
    doc["catalog"]["limit_per_project"] = s.catalog.limit_per_project
    doc.add("billing", tomlkit.table())
    doc["billing"]["export_dataset"] = s.billing.export_dataset
    doc.add("labels", tomlkit.table())
    doc["labels"]["owner"] = s.labels.owner
    doc["labels"]["cost_center"] = s.labels.cost_center
    doc["labels"]["env"] = s.labels.env
    doc.add("redaction", tomlkit.table())
    doc["redaction"]["enabled"] = s.redaction.enabled
    doc.add("refresh", tomlkit.table())
    doc["refresh"]["cadence"] = s.refresh.cadence
    doc.add("credentials", tomlkit.table())
    doc["credentials"]["sa_key_path"] = s.credentials.sa_key_path or ""
    doc["credentials"]["impersonate_service_account"] = (
        s.credentials.impersonate_service_account or ""
    )
    doc["credentials"]["quota_project"] = s.credentials.quota_project or ""
    doc.add("security", tomlkit.table())
    doc["security"]["prowler_bin"] = s.security.prowler_bin
    doc["security"]["api_url"] = s.security.api_url
    doc["security"]["api_token"] = s.security.api_token
    doc["security"]["timeout_sec"] = s.security.timeout_sec
    doc.add("reports", tomlkit.table())
    doc["reports"]["out_base"] = s.reports.out_base
    doc["reports"]["formats"] = s.reports.formats
    doc["reports"]["default_date"] = s.reports.default_date
    doc.add("output", tomlkit.table())
    doc["output"]["base_dir"] = s.output.base_dir
    doc["output"]["summary_path"] = s.output.summary_path
    doc["output"]["slides_dir"] = s.output.slides_dir
    doc["output"]["csv_dir"] = s.output.csv_dir
    doc["output"]["access_dir"] = s.output.access_dir
    doc["output"]["raw_dir"] = s.output.raw_dir
    doc.add("metadata", tomlkit.table())
    doc["metadata"]["author"] = s.metadata.author
    doc["metadata"]["version"] = s.metadata.version
    doc.add("decommission", tomlkit.table())
    doc["decommission"]["bucket_whitelist"] = s.decommission.bucket_whitelist
    with open(cfg_path, "w") as f:
        f.write(tomlkit.dumps(doc))
    return cfg_path


def get_cli_defaults(s: Settings, cfg_path: Optional[str] = None) -> dict:
    from datetime import datetime, timezone

    cfg_dir = os.path.dirname(locate_config(cfg_path) or "")
    def_date = s.reports.default_date or "now"
    date_resolved = (
        datetime.now(timezone.utc).strftime("%Y%m%d") if def_date == "now" else def_date
    )
    assets_bin = (
        os.path.join(cfg_dir, s.security.prowler_bin)
        if cfg_dir
        else s.security.prowler_bin
    )
    return {
        "author": s.metadata.author or "Iñaki Marín",
        "report_date": date_resolved,
        "out_base": s.reports.out_base or s.output.base_dir or "reports",
        "projects": s.catalog.projects,
        "org_id": s.org.org_id,
        "formats": s.reports.formats or ["md", "json", "csv"],
        "sa_key": s.credentials.sa_key_path,
        "prowler_bin": assets_bin,
        "api_url": s.security.api_url,
        "api_token": s.security.api_token,
    }
