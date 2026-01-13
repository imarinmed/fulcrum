from typer.testing import CliRunner
from ..src.cli import app

runner = CliRunner()

def test_security_ingest_and_validate(tmp_path, monkeypatch):
    import fulcrum.core.reporting as rep
    def fake_collect_all(sa_key_path=None):
        return {"p1": {"instances": [], "networks": [], "firewalls": [], "buckets": [], "sql_instances": [], "iam_policy": [{"bindings": []}]}}
    monkeypatch.setattr(rep, "collect_all", fake_collect_all)
    prowler_json = tmp_path / "prowler.json"
    prowler_json.write_text('[{"check_id":"gcp_storage_bucket_public","service":"gcs","status":"FAIL","resource_id":"b1","project_id":"p1","severity":"high"}]')
    result = runner.invoke(app, ["reports", "security", "ingest", "--out-base", str(tmp_path / "reports"), "--report-date", "20250101", "--prowler-json", str(prowler_json)])
    assert result.exit_code == 0
    result = runner.invoke(app, ["reports", "security", "validate", "--path", str(tmp_path / "reports")])
    assert result.exit_code == 0

def test_security_run_missing_prowler(tmp_path, monkeypatch):
    import fulcrum.prowler.runner as pr
    def fake_which(arg):
        return None
    monkeypatch.setattr(pr.shutil, "which", fake_which)
    result = runner.invoke(app, ["reports", "security", "run", "--out-base", str(tmp_path / "reports"), "--report-date", "20250101"])
    assert result.exit_code == 0
