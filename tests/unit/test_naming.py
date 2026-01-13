import os
import tempfile
from src.core.reporting import ensure_report_dir

def test_typed_std_dir_name():
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "reports")
        os.makedirs(base, exist_ok=True)
        d = ensure_report_dir(base, report_date="20250101", rtype="std")
        assert os.path.basename(d) == "report-std-20250101"

def test_typed_sec_dir_name():
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "reports")
        os.makedirs(base, exist_ok=True)
        d = ensure_report_dir(base, report_date="20250101", rtype="sec")
        assert os.path.basename(d) == "report-sec-20250101"

def test_duplicate_suffix_increment():
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "reports")
        os.makedirs(base, exist_ok=True)
        first = ensure_report_dir(base, report_date="20250101", rtype="std")
        # create a file to make it non-empty and collide
        with open(os.path.join(first, "index.md"), "w") as f:
            f.write("x")
        second = ensure_report_dir(base, report_date="20250101", rtype="std")
        assert os.path.basename(second).startswith("report-std-20250101-")
