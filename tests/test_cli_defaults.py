import os
import sys
from datetime import datetime, timezone

def test_get_cli_defaults_now(tmp_path, monkeypatch):
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from src.core.settings import Settings, save_settings, load_settings, get_cli_defaults
    cfg = tmp_path / "fulcrum.toml"
    s = Settings()
    s.metadata.author = "Iñaki Marín"
    s.reports.out_base = "reports"
    s.reports.default_date = "now"
    path = save_settings(cfg.as_posix(), s)
    assert os.path.exists(path)
    s2 = load_settings(cfg.as_posix())
    d = get_cli_defaults(s2, cfg.as_posix())
    assert d["author"] == "Iñaki Marín"
    assert d["report_date"] == datetime.now(timezone.utc).strftime("%Y%m%d")

def test_preflight_prowler_bin_resolution(tmp_path, monkeypatch):
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from src.core.settings import Settings, save_settings, load_settings, get_cli_defaults
    cfg = tmp_path / "fulcrum.toml"
    assets_dir = tmp_path / "assets" / "prowler"
    assets_dir.mkdir(parents=True)
    prowler_path = assets_dir / "prowler"
    prowler_path.write_text("#!/bin/sh\necho prowler\n")
    os.chmod(prowler_path.as_posix(), 0o755)
    s = Settings()
    s.security.prowler_bin = "assets/prowler/prowler"
    path = save_settings(cfg.as_posix(), s)
    s2 = load_settings(cfg.as_posix())
    d = get_cli_defaults(s2, cfg.as_posix())
    assert os.path.exists(d["prowler_bin"]) and os.access(d["prowler_bin"], os.X_OK)
