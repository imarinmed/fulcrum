import os
from datetime import datetime, timezone
from typer.testing import CliRunner
from fulcrum.cli import app

runner = CliRunner()


def test_security_run_defaults_report_date(tmp_path, monkeypatch):
    # Mock API availability and results to exercise API path writing to data_dir
    import fulcrum.prowler.api as api

    monkeypatch.setattr(api, "is_api_available", lambda base_url, token: True)
    monkeypatch.setattr(
        api,
        "run_scan_api",
        lambda base_url, token, provider, projects, org_id: {
            "job_id": "1",
            "results": "[]",
        },
    )
    # Run without --report-date
    out_base = tmp_path / "reports"
    result = runner.invoke(
        app,
        [
            "reports",
            "security",
            "run",
            "--out-base",
            str(out_base),
            "--api-url",
            "https://prowler.example",
            "--api-token",
            "token123",
        ],
    )
    assert result.exit_code == 0
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    data_dir = out_base / f"report-{today}" / "data"
    assert os.path.isdir(data_dir)
    assert os.path.isfile(data_dir / "prowler.json")
