import os
from src.core.catalog import read_csv, validate_csvs


def test_read_csv_missing(tmp_path):
    p = tmp_path / "missing.csv"
    rows = read_csv(str(p))
    assert rows == []


def test_validate_csvs(tmp_path):
    out = tmp_path
    os.makedirs(out / "csv")
    os.makedirs(out / "access")
    with open(out / "csv" / "compute.csv", "w") as f:
        f.write("project_id,resource_name\n")
    with open(out / "csv" / "storage.csv", "w") as f:
        f.write("project_id,name\n")
    with open(out / "access" / "iam_matrix.csv", "w") as f:
        f.write("project_id,principal\n")
    issues = validate_csvs(str(out))
    assert issues == []
