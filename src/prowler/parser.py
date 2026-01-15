import os
import json
import csv
from typing import Dict, List, Tuple
import structlog

from .models import RawProwlerFinding

log = structlog.get_logger()


def load_json(path: str) -> List[RawProwlerFinding]:
    """
    Load Prowler findings from a JSON file.

    Args:
        path: Path to the JSON file.

    Returns:
        List of RawProwlerFinding objects.
    """
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            log.warning(
                "prowler.json_parse_error", path=path, error=str(e), security_event=True
            )
            return []
    if isinstance(data, list):
        return [RawProwlerFinding(**item) for item in data]
    if isinstance(data, dict) and "results" in data:
        return [RawProwlerFinding(**item) for item in data.get("results", [])]
    return []


def load_csv(path: str) -> List[RawProwlerFinding]:
    """
    Load Prowler findings from a CSV file.

    Args:
        path: Path to the CSV file.

    Returns:
        List of RawProwlerFinding objects.
    """
    if not path or not os.path.isfile(path):
        return []
    with open(path, newline="") as f:
        try:
            reader = csv.DictReader(f)
            return [RawProwlerFinding(**row) for row in reader]
        except (csv.Error, TypeError, ValueError) as e:
            log.warning(
                "prowler.csv_parse_error", path=path, error=str(e), security_event=True
            )
            return []


def parse(inputs: List[Tuple[str, str]]) -> List[RawProwlerFinding]:
    """
    Parse Prowler output files (JSON or CSV) into structured findings.

    Args:
        inputs: List of tuples containing (format, path) pairs.
                Format should be "json" or "csv".

    Returns:
        List of RawProwlerFinding objects with type-safe accessors.
    """
    items: List[RawProwlerFinding] = []
    for kind, path in inputs:
        if kind == "json":
            items.extend(load_json(path))
        elif kind == "csv":
            items.extend(load_csv(path))
    return items
