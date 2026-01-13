import importlib
import pytest
from typer.testing import CliRunner

def test_help():
    try:
        app = importlib.import_module("fulcrum.cli").app
    except Exception:
        pytest.skip("CLI dependencies not available")
    runner = CliRunner()
    result = runner.invoke(app, ["--help"]) 
    assert result.exit_code == 0
