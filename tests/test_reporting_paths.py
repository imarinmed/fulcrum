import os
from src.core.reporting import ensure_report_dir


def test_ensure_report_dir_default(tmp_path):
    base = tmp_path / "reports"
    path = ensure_report_dir(str(base), "20250101")
    assert os.path.isdir(path)
    assert os.path.basename(path) == "report-20250101"


def test_ensure_report_dir_reject_traversal(tmp_path):
    try:
        ensure_report_dir("../outside")
    except ValueError:
        assert True
    else:
        assert False
