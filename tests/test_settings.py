import os
from src.core.settings import load_settings, save_settings, Settings


def test_settings_roundtrip(tmp_path):
    path = tmp_path / "fulcrum.toml"
    s = Settings()
    s.org.org_id = "308776007368"
    s.catalog.projects = ["proj-a", "proj-b"]
    saved = save_settings(str(path), s)
    assert os.path.exists(saved)
    s2 = load_settings(str(path))
    assert s2.org.org_id == "308776007368"
    assert s2.catalog.projects == ["proj-a", "proj-b"]
