import re
import os
import json
from typing import List, Dict, Any
import structlog

log = structlog.get_logger()

class SecurityAuditor:
    def __init__(self, root_path: str):
        self.root_path = root_path
        self.patterns = {
            "api_key": r"(?i)(api_key|apikey|secret_key|access_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
            "password": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{1,}['\"]",
            "db_connection": r"(?i)(postgres|mysql)://.*:.*@",
            "private_key": r"-----BEGIN PRIVATE KEY-----"
        }
        self.ignore_dirs = {".git", "__pycache__", "venv", "node_modules", ".trae"}
        self.ignore_files = {"package-lock.json", "yarn.lock"}

    def scan(self) -> List[Dict[str, Any]]:
        findings = []
        log.info("security.audit_start", path=self.root_path)

        for root, dirs, files in os.walk(self.root_path):
            # Prune ignored dirs
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]

            for file in files:
                if file in self.ignore_files:
                    continue
                
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for rule_name, pattern in self.patterns.items():
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                findings.append({
                                    "file": file_path,
                                    "rule": rule_name,
                                    "line": content[:match.start()].count('\n') + 1,
                                    "match_snippet": match.group(0)[:50] + "..." # Truncate for safety report
                                })
                except Exception as e:
                    log.warning("security.audit_file_error", file=file_path, error=str(e))
        
        return findings
