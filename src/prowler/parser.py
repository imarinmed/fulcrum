import os
import json
import csv
from typing import Dict, List, Tuple

def load_json(path: str) -> List[Dict]:
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r") as f:
        try:
            data = json.load(f)
        except Exception:
            return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "results" in data:
        return data.get("results", [])
    return []

def load_csv(path: str) -> List[Dict]:
    if not path or not os.path.isfile(path):
        return []
    with open(path, newline="") as f:
        try:
            reader = csv.DictReader(f)
            return list(reader)
        except Exception:
            return []

def parse(inputs: List[Tuple[str, str]]) -> List[Dict]:
    items: List[Dict] = []
    for kind, path in inputs:
        if kind == "json":
            items.extend(load_json(path))
        elif kind == "csv":
            items.extend(load_csv(path))
    return items

