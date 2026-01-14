from typer.testing import CliRunner
from src.cli import app


def test_config_init_show(tmp_path):
    runner = CliRunner()
    cfg = tmp_path / "fulcrum.toml"
    r1 = runner.invoke(app, ["config", "init", "--config", str(cfg)])
    assert r1.exit_code == 0
    r2 = runner.invoke(app, ["config", "show", "--config", str(cfg)])
    assert r2.exit_code == 0
    r3 = runner.invoke(
        app, ["config", "set-org-id", "308776007368", "--config", str(cfg)]
    )
    assert r3.exit_code == 0
    r4 = runner.invoke(app, ["config", "add-project", "proj-a", "--config", str(cfg)])
    assert r4.exit_code == 0
