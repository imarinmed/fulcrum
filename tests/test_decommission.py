import pytest
from unittest.mock import MagicMock, patch
from src.gcp.decommission import Decommissioner, SecurityError
from src.core.settings import DecommissionSettings, Settings


@pytest.fixture
def mock_settings():
    settings = Settings()
    settings.decommission.bucket_whitelist = ["safe-bucket"]
    return settings


@patch("src.gcp.decommission.load_settings")
@patch("src.gcp.decommission.run_gcloud_json")
def test_decommission_safety_check_fails(mock_run, mock_load, mock_settings):
    """Test that empty whitelist raises SecurityError without force flag."""
    # Setup empty whitelist
    mock_settings.decommission.bucket_whitelist = []
    mock_load.return_value = mock_settings

    decom = Decommissioner("test-project")

    # Mock audit to return a bucket
    mock_run.return_value = [{"id": "gs://unsafe-bucket/"}]

    with pytest.raises(SecurityError, match="Unsafe to destroy resources"):
        decom.destroy_resources(dry_run=False)


@patch("src.gcp.decommission.load_settings")
@patch("src.gcp.decommission.run_gcloud_json")
def test_decommission_whitelist_preserves(mock_run, mock_load, mock_settings):
    """Test that whitelisted buckets are preserved."""
    mock_load.return_value = mock_settings
    decom = Decommissioner("test-project")

    # Mock audit with one safe and one unsafe bucket
    # Note: run_gcloud_json is called multiple times. We need to handle that.
    # 1. GKE (empty)
    # 2. SQL (empty)
    # 3. Buckets
    # 4. Networking (empty)
    mock_run.side_effect = [
        [],  # GKE
        [],  # SQL
        [{"id": "gs://safe-bucket/"}, {"id": "gs://unsafe-bucket/"}],  # Buckets
        [],  # Networking
    ]

    report = decom.audit_resources()

    buckets = {b["name"]: b["action"] for b in report["buckets"]}
    assert buckets["safe-bucket"] == "PRESERVE"
    assert buckets["unsafe-bucket"] == "DELETE"


@patch("src.gcp.decommission.load_settings")
@patch("src.gcp.decommission.run_gcloud_json")
@patch("src.gcp.decommission.subprocess.run")
def test_decommission_execution(mock_subprocess, mock_run, mock_load, mock_settings):
    """Test that delete commands are generated correctly."""
    mock_load.return_value = mock_settings
    decom = Decommissioner("test-project")

    mock_run.side_effect = [[], [], [{"id": "gs://unsafe-bucket/"}], []]

    decom.destroy_resources(dry_run=False)

    # Verify subprocess called for unsafe bucket
    # We expect: gcloud storage rm -r gs://unsafe-bucket ...
    # And check that it was NOT shell=True

    assert mock_subprocess.call_count == 1
    args, kwargs = mock_subprocess.call_args
    cmd = args[0]

    assert "gcloud" in cmd
    assert "storage" in cmd
    assert "gs://unsafe-bucket" in cmd
    assert kwargs.get("shell") is not True  # Ensure shell=True is NOT used
