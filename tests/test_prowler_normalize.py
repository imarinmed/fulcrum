from src.prowler.normalize import to_canonical


def test_normalize_basics():
    items = [
        {
            "check_id": "gcp_storage_bucket_public",
            "service": "gcs",
            "status": "FAIL",
            "resource_id": "b1",
            "project_id": "p1",
            "severity": "high",
        }
    ]
    out = to_canonical(items)
    # Framework is UNKNOWN because DataProtection is not a valid enum value
    assert out[0].framework == "unknown"
    assert out[0].severity == "high"
